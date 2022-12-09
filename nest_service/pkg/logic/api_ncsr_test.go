package nest_service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/assert/v2"
	nest_ca "github.com/m4rkdc/nebula_est/nest_ca/pkg/logic"
	nest_config "github.com/m4rkdc/nebula_est/nest_config/pkg/logic"
	"github.com/m4rkdc/nebula_est/nest_service/pkg/models"
	"github.com/m4rkdc/nebula_est/nest_service/pkg/utils"
	nest_test "github.com/m4rkdc/nebula_est/nest_service/test"
	"github.com/slackhq/nebula/cert"
)

func sendNcsrApplication(t *testing.T, r *gin.Engine, endpoint models.Route, auth models.NestAuth) *httptest.ResponseRecorder {
	authBytes, _ := json.Marshal(auth)
	req, _ := http.NewRequest(endpoint.Method, endpoint.Pattern, bytes.NewReader(authBytes))
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	return resp
}

func sendEnroll(t *testing.T, r *gin.Engine, endpoint models.Route, hostname string, csr *models.NebulaCsr) *httptest.ResponseRecorder {
	var req *http.Request
	url := strings.ReplaceAll(endpoint.Pattern, ":hostname", hostname)
	if csr == nil {
		req, _ = http.NewRequest(endpoint.Method, url, http.NoBody)
	} else {
		csr_bytes, _ := json.Marshal(csr)
		req, _ = http.NewRequest(endpoint.Method, url, bytes.NewReader(csr_bytes))
	}
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	return resp
}

/*
func sendNcsrStatus(t *testing.T, r *gin.Engine, endpoint models.Route, hostname string) *httptest.ResponseRecorder {
	var req *http.Request
	url := strings.ReplaceAll(endpoint.Pattern, ":hostname", hostname)
	req, _ = http.NewRequest(endpoint.Method, url, http.NoBody)
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	return resp
}*/

func TestNcsrApplication(t *testing.T) {
	var (
		endpoint models.Route = Service_routes[1]
		auth     models.NestAuth
		err      models.ApiError
	)

	r := nest_test.MockRouterForEndpoint(&endpoint)

	//First test: request without hostname
	auth = models.NestAuth{Secret: []byte("abc")}
	err = models.ApiError{Code: 400, Message: "Bad request: no client authorization provided"}
	errBytes, _ := json.Marshal(err)
	resp := sendNcsrApplication(t, r, endpoint, auth)
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Equal(t, errBytes, resp.Body.Bytes())

	//Second test: hostname already enrolled
	utils.Ncsr_folder = "../../test/ncsr/"

	auth.Hostname = "abc"
	err = models.ApiError{Code: 409, Message: "Conflict. A Nebula CSR for the hostname you provided already exists. If you want to re-enroll, please visit https://" + utils.Service_ip + ":" + utils.Service_port + "/ncsr/" + auth.Hostname + "/reenroll"}
	errBytes, _ = json.Marshal(err)
	resp = sendNcsrApplication(t, r, endpoint, auth)
	assert.Equal(t, http.StatusConflict, resp.Code)
	assert.Equal(t, errBytes, resp.Body.Bytes())

	//Third test: cannot find hostnames file
	auth.Hostname = "jack"
	resp = sendNcsrApplication(t, r, endpoint, auth)
	assert.Equal(t, http.StatusInternalServerError, resp.Code)

	//Fourth test: hostname is not valid
	utils.Hostnames_file = "../../test/config/hostnames"
	err = models.ApiError{Code: 400, Message: "Bad request: The hostname you provided was not found in the Configuration service list"}
	errBytes, _ = json.Marshal(err)
	resp = sendNcsrApplication(t, r, endpoint, auth)
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Equal(t, errBytes, resp.Body.Bytes())

	//Fifth test: cannot find key
	os.Remove(utils.Ncsr_folder + "lighthouse")
	auth.Hostname = "lighthouse"
	auth.Secret = sign("abc")
	resp = sendNcsrApplication(t, r, endpoint, auth)
	assert.Equal(t, http.StatusInternalServerError, resp.Code)

	utils.HMAC_key = "../../test/config/hmac.key"
	//Sixth test: secret is not valid
	auth.Secret = sign("abc")
	err = models.ApiError{Code: 400, Message: "Bad Request. Could not succesfully verify the provided secret"}
	errBytes, _ = json.Marshal(err)
	resp = sendNcsrApplication(t, r, endpoint, auth)
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Equal(t, errBytes, resp.Body.Bytes())

	//Seventh test: success
	auth.Secret = sign(auth.Hostname)
	fmt.Println(auth.Secret)
	resp = sendNcsrApplication(t, r, endpoint, auth)
	assert.Equal(t, http.StatusCreated, resp.Code)
	assert.Equal(t, "http://"+utils.Service_ip+":"+utils.Service_port+"/ncsr/"+auth.Hostname, resp.Header().Get("Location"))
}

func TestEnroll(t *testing.T) {
	var (
		csr             = &models.NebulaCsr{}
		endpoint        = Service_routes[2]
		ca_endpoint     = nest_ca.Ca_routes[1]
		config_endpoint = nest_config.Conf_routes[1]
		err             models.ApiError
		hostname        string
		errTest         models.ApiError
	)

	r := nest_test.MockRouterForEndpoint(&endpoint)
	utils.Ncsr_folder = "../../test/ncsr/"
	applicationFile, _ := os.OpenFile(utils.Ncsr_folder+"lighthouse", os.O_CREATE|os.O_WRONLY, 0600)
	applicationFile.WriteString(string(models.PENDING))
	//First test: empty hostname
	hostname = " "
	err = models.ApiError{Code: 400, Message: "Bad request: no hostname provided"}
	errBytes, _ := json.Marshal(err)
	resp := sendEnroll(t, r, endpoint, hostname, csr)
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Equal(t, errBytes, resp.Body.Bytes())

	//Second test: not authorized
	hostname = "prova"
	err = models.ApiError{Code: 401, Message: "Unhautorized: please authenticate yourself to https://" + utils.Service_ip + ":" + utils.Service_port + "/ncsr providing your hostname and secret, before accessing this endpoint"}
	errBytes, _ = json.Marshal(err)
	resp = sendEnroll(t, r, endpoint, hostname, csr)
	assert.Equal(t, http.StatusUnauthorized, resp.Code)
	assert.Equal(t, errBytes, resp.Body.Bytes())

	//Third test: hostname already enrolled
	hostname = "abc"
	err = models.ApiError{Code: 409, Message: "Conflict. This hostname has already enrolled. If you want to re-enroll, please visit https://" + utils.Service_ip + ":" + utils.Service_port + "/ncsr/" + hostname + "/reenroll"}
	errBytes, _ = json.Marshal(err)
	resp = sendEnroll(t, r, endpoint, hostname, csr)
	assert.Equal(t, http.StatusConflict, resp.Code)
	assert.Equal(t, errBytes, resp.Body.Bytes())

	//Fourth test: no Nebula CSR
	hostname = "lighthouse"
	utils.Hostnames_file = "../../test/config/hostnames"
	err = models.ApiError{Code: 400, Message: "Bad request: no Nebula Certificate Signing Request provided"}
	resp = sendEnroll(t, r, endpoint, hostname, nil)
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	json.Unmarshal(resp.Body.Bytes(), &errTest)
	assert.Equal(t, err.Code, errTest.Code)
	assert.Equal(t, err.Message, errTest.Message)

	//Fifth test: different hostnames in csr and url
	err = models.ApiError{Code: 403, Message: "Forbidden. The hostname in the URL and the one in the Nebula CSR are different."}
	errBytes, _ = json.Marshal(err)
	csr.Hostname = "lalal"
	resp = sendEnroll(t, r, endpoint, hostname, csr)
	assert.Equal(t, http.StatusForbidden, resp.Code)
	assert.Equal(t, errBytes, resp.Body.Bytes())

	//Sixth test: rekey is true but not reenroll
	err = models.ApiError{Code: 400, Message: "Bad Request. Rekey is true"}
	errBytes, _ = json.Marshal(err)
	csr.Hostname = hostname
	csr.Rekey = true
	resp = sendEnroll(t, r, endpoint, hostname, csr)
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Equal(t, errBytes, resp.Body.Bytes())

	//Seventh test: simple enroll but serverkeygen is true
	err = models.ApiError{Code: 400, Message: "Bad Request. ServerKeygen is true. If you wanted to enroll with a server keygen, please visit https://" + utils.Service_ip + ":" + utils.Service_port + "/" + "/ncsr/" + hostname + "/serverkeygen"}
	errBytes, _ = json.Marshal(err)
	csr.Rekey = false
	csr.ServerKeygen = true
	resp = sendEnroll(t, r, endpoint, hostname, csr)
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Equal(t, errBytes, resp.Body.Bytes())

	//Eighth test: public key not provided
	err = models.ApiError{Code: 400, Message: "Bad Request. Public key is not provided"}
	errBytes, _ = json.Marshal(err)
	csr.ServerKeygen = false
	resp = sendEnroll(t, r, endpoint, hostname, csr)
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Equal(t, errBytes, resp.Body.Bytes())

	//Ninth test: success

	r2 := nest_test.MockRouterForEndpoint(&ca_endpoint)
	utils.Certificates_path = "../../../nest_ca/testcertificates/"
	os.Remove(utils.Certificates_path + csr.Hostname + ".crt")
	utils.Ca_bin = "../../../nest_ca/test/config/bin/"
	utils.Ca_keys_path = "../../../nest_ca/test/config/keys/"
	utils.Ca_service_ip = "localhost"
	utils.Ca_service_port = "8083"
	go r2.Run(utils.Ca_service_ip + ":" + utils.Ca_service_port)
	r3 := nest_test.MockRouterForEndpoint(&config_endpoint)
	utils.Dhall_dir = "../../../nest_config/test/dhall/"
	utils.Dhall_configuration = utils.Dhall_dir + "nebula/nebula_conf.dhall"
	utils.Conf_service_ip = "localhost"
	utils.Conf_service_port = "8081"
	go r3.Run(utils.Conf_service_ip + ":" + utils.Conf_service_port)

	b, _ := os.ReadFile("../../test/lighthouse.pub")
	csr.PublicKey, _, _ = cert.UnmarshalX25519PublicKey(b)
	fmt.Println(csr.PublicKey)
	resp = sendEnroll(t, r, endpoint, hostname, csr)
	assert.Equal(t, http.StatusOK, resp.Code)

}

func TestNcsrStatus(t *testing.T) {

}
func TestReenroll(t *testing.T) {
	var (
		csr                      = &models.NebulaCsr{}
		endpoint    models.Route = Service_routes[4]
		ca_endpoint models.Route = nest_ca.Ca_routes[2]
		err         models.ApiError
		hostname    string
		errTest     models.ApiError
	)

	r := nest_test.MockRouterForEndpoint(&endpoint)

	//First test: empty hostname
	hostname = " "
	err = models.ApiError{Code: 400, Message: "Bad request: no hostname provided"}
	errBytes, _ := json.Marshal(err)
	resp := sendEnroll(t, r, endpoint, hostname, csr)
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Equal(t, errBytes, resp.Body.Bytes())

	//Second test: not authorized
	hostname = "prova"
	utils.Ncsr_folder = "../../test/ncsr/"
	err = models.ApiError{Code: 401, Message: "Unhautorized: please authenticate yourself to https://" + utils.Service_ip + ":" + utils.Service_port + "/ncsr providing your hostname and secret, before accessing this endpoint"}
	errBytes, _ = json.Marshal(err)
	resp = sendEnroll(t, r, endpoint, hostname, csr)
	assert.Equal(t, http.StatusUnauthorized, resp.Code)
	assert.Equal(t, errBytes, resp.Body.Bytes())

	//Third test: hostname not finished enrolling
	hostname = "pending"
	err = models.ApiError{Code: 409, Message: "Conflict. This hostname has not yet finished enrolling. If you want to do so, please visit https://" + utils.Service_ip + ":" + utils.Service_port + "/ncsr/" + hostname + "/enroll"}
	errBytes, _ = json.Marshal(err)
	resp = sendEnroll(t, r, endpoint, hostname, csr)
	assert.Equal(t, http.StatusConflict, resp.Code)
	assert.Equal(t, errBytes, resp.Body.Bytes())

	//Fourth test: no Nebula CSR
	hostname = "lighthouse"
	utils.Hostnames_file = "../../test/config/hostnames"
	err = models.ApiError{Code: 400, Message: "Bad request: no Nebula Certificate Signing Request provided"}
	resp = sendEnroll(t, r, endpoint, hostname, nil)
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	json.Unmarshal(resp.Body.Bytes(), &errTest)
	assert.Equal(t, err.Code, errTest.Code)
	assert.Equal(t, err.Message, errTest.Message)

	//Fifth test: different hostnames in csr and url
	err = models.ApiError{Code: 403, Message: "Forbidden. The hostname in the URL and the one in the Nebula CSR are different."}
	errBytes, _ = json.Marshal(err)
	csr.Hostname = "lalal"
	resp = sendEnroll(t, r, endpoint, hostname, csr)
	assert.Equal(t, http.StatusForbidden, resp.Code)
	assert.Equal(t, errBytes, resp.Body.Bytes())

	//Sixth test: reenroll and rekey is true, serverkeygen is false but public key is empty
	err = models.ApiError{Code: 400, Message: "Bad Request. Public key is not provided"}
	errBytes, _ = json.Marshal(err)
	csr.Hostname = hostname
	csr.Rekey = true
	resp = sendEnroll(t, r, endpoint, hostname, csr)
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Equal(t, errBytes, resp.Body.Bytes())

	//Eigth test: success with serverkeygen
	r2 := nest_test.MockRouterForEndpoint(&ca_endpoint)
	utils.Certificates_path = "../../../nest_ca/test/certificates/"
	os.Remove(utils.Certificates_path + csr.Hostname + ".crt")
	utils.Ca_bin = "../../../nest_ca/test/config/bin/"
	utils.Ca_keys_path = "../../../nest_ca/test/config/keys/"
	utils.Ca_service_ip = "localhost"
	utils.Ca_service_port = "8085"
	go r2.Run(utils.Ca_service_ip + ":" + utils.Ca_service_port)
	csr.ServerKeygen = true
	resp = sendEnroll(t, r, endpoint, hostname, csr)
	fmt.Println(resp.Body)
	assert.Equal(t, http.StatusOK, resp.Code)

	//Eigth test: success with simple reenroll
	ca_endpoint = nest_ca.Ca_routes[1]
	r2 = nest_test.MockRouterForEndpoint(&ca_endpoint)
	utils.Certificates_path = "../../../nest_ca/test/certificates/"
	os.Remove(utils.Certificates_path + csr.Hostname + ".crt")
	utils.Ca_bin = "../../../nest_ca/test/config/bin/"
	utils.Ca_keys_path = "../../../nest_ca/test/config/keys/"
	go r2.Run(utils.Ca_service_ip + ":" + utils.Ca_service_port)

	b, _ := os.ReadFile("../../test/lighthouse.pub")
	csr.PublicKey, _, _ = cert.UnmarshalX25519PublicKey(b)
	resp = sendEnroll(t, r, endpoint, hostname, csr)
	fmt.Println(resp.Body)
	assert.Equal(t, http.StatusOK, resp.Code)

}
func TestServerkeygen(t *testing.T) {
	var (
		csr                          = &models.NebulaCsr{}
		endpoint        models.Route = Service_routes[5]
		ca_endpoint     models.Route = nest_ca.Ca_routes[2]
		config_endpoint models.Route = nest_config.Conf_routes[1]
		err             models.ApiError
		hostname        string
		errTest         models.ApiError
	)

	r := nest_test.MockRouterForEndpoint(&endpoint)
	applicationFile, _ := os.OpenFile(utils.Ncsr_folder+"lighthouse", os.O_CREATE|os.O_WRONLY, 0600)
	applicationFile.WriteString(string(models.PENDING))

	//First test: empty hostname
	hostname = " "
	err = models.ApiError{Code: 400, Message: "Bad request: no hostname provided"}
	errBytes, _ := json.Marshal(err)
	resp := sendEnroll(t, r, endpoint, hostname, csr)
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Equal(t, errBytes, resp.Body.Bytes())

	//Second test: not authorized
	hostname = "prova"
	utils.Ncsr_folder = "../../test/ncsr/"
	err = models.ApiError{Code: 401, Message: "Unhautorized: please authenticate yourself to https://" + utils.Service_ip + ":" + utils.Service_port + "/ncsr providing your hostname and secret, before accessing this endpoint"}
	errBytes, _ = json.Marshal(err)
	resp = sendEnroll(t, r, endpoint, hostname, csr)
	assert.Equal(t, http.StatusUnauthorized, resp.Code)
	assert.Equal(t, errBytes, resp.Body.Bytes())

	//Third test: hostname already enrolled
	hostname = "abc"
	err = models.ApiError{Code: 409, Message: "Conflict. This hostname has already enrolled. If you want to re-enroll, please visit https:https://" + utils.Service_ip + ":" + utils.Service_port + "/ncsr/" + hostname + "/reenroll"}
	errBytes, _ = json.Marshal(err)
	resp = sendEnroll(t, r, endpoint, hostname, csr)
	assert.Equal(t, http.StatusConflict, resp.Code)
	assert.Equal(t, errBytes, resp.Body.Bytes())

	//Fourth test: no Nebula CSR
	hostname = "lighthouse"
	utils.Hostnames_file = "../../test/config/hostnames"
	err = models.ApiError{Code: 400, Message: "Bad request: no Nebula Certificate Signing Request provided"}
	resp = sendEnroll(t, r, endpoint, hostname, nil)
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	json.Unmarshal(resp.Body.Bytes(), &errTest)
	assert.Equal(t, err.Code, errTest.Code)
	assert.Equal(t, err.Message, errTest.Message)

	//Fifth test: different hostnames in csr and url
	err = models.ApiError{Code: 403, Message: "Forbidden. The hostname in the URL and the one in the Nebula CSR are different."}
	errBytes, _ = json.Marshal(err)
	csr.Hostname = "lalal"
	resp = sendEnroll(t, r, endpoint, hostname, csr)
	assert.Equal(t, http.StatusForbidden, resp.Code)
	assert.Equal(t, errBytes, resp.Body.Bytes())

	//Sixth test: rekey is true but not reenroll
	err = models.ApiError{Code: 400, Message: "Bad Request. Rekey is true"}
	errBytes, _ = json.Marshal(err)
	csr.Hostname = hostname
	csr.Rekey = true
	resp = sendEnroll(t, r, endpoint, hostname, csr)
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Equal(t, errBytes, resp.Body.Bytes())

	//Seventh test: serverkeygen enroll but serverkeygen is false
	err = models.ApiError{Code: 400, Message: "Bad Request. ServerKeygen is false. If you wanted to enroll with a client-generated nebula public key, please visit https://" + utils.Service_ip + ":" + utils.Service_port + "/" + "/ncsr/" + hostname + "/enroll"}
	errBytes, _ = json.Marshal(err)
	csr.Rekey = false
	resp = sendEnroll(t, r, endpoint, hostname, csr)
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Equal(t, errBytes, resp.Body.Bytes())

	//Eighth test: success
	r2 := nest_test.MockRouterForEndpoint(&ca_endpoint)
	utils.Certificates_path = "../../../nest_ca/test/certificates/"
	os.Remove(utils.Certificates_path + csr.Hostname + ".crt")
	utils.Ca_bin = "../../../nest_ca/test/config/bin/"
	utils.Ca_keys_path = "../../../nest_ca/test/config/keys/"
	utils.Ca_service_ip = "localhost"
	utils.Ca_service_port = "8082"
	go r2.Run(utils.Ca_service_ip + ":" + utils.Ca_service_port)
	r3 := nest_test.MockRouterForEndpoint(&config_endpoint)
	utils.Dhall_dir = "../../../nest_config/test/dhall/"
	utils.Dhall_configuration = utils.Dhall_dir + "nebula/nebula_conf.dhall"
	utils.Conf_service_ip = "localhost"
	utils.Conf_service_port = "8087"
	go r3.Run(utils.Conf_service_ip + ":" + utils.Conf_service_port)

	csr.ServerKeygen = true
	resp = sendEnroll(t, r, endpoint, hostname, csr)
	fmt.Println(resp.Body)
	assert.Equal(t, http.StatusOK, resp.Code)

}
