package nest_ca

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/assert/v2"
	"github.com/m4rkdc/nebula_est/nest_service/pkg/models"
	"github.com/m4rkdc/nebula_est/nest_service/pkg/utils"
	nest_test "github.com/m4rkdc/nebula_est/nest_service/test"
	"github.com/slackhq/nebula/cert"
)

func sendCertificateSign(t *testing.T, r *gin.Engine, endpoint models.Route, csr *models.NebulaCsr) *httptest.ResponseRecorder {
	var req *http.Request
	if csr == nil {
		req, _ = http.NewRequest(endpoint.Method, endpoint.Pattern, http.NoBody)
	} else {
		csr_bytes, _ := json.Marshal(csr)
		req, _ = http.NewRequest(endpoint.Method, endpoint.Pattern, bytes.NewReader(csr_bytes))
	}

	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	return resp
}

func TestCertificateSign(t *testing.T) {
	var (
		endpoint models.Route = Ca_routes[1]
		err      models.ApiError
		csr      = models.NebulaCsr{}
	)

	r := nest_test.MockRouterForEndpoint(&endpoint)

	//First test: request without csr
	err = models.ApiError{Code: 400, Message: "Bad request: no Nebula Certificate Signing Request provided"}
	errBytes, _ := json.Marshal(err)
	resp := sendCertificateSign(t, r, endpoint, nil)
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Equal(t, errBytes, resp.Body.Bytes())

	//Second test: enroll csr success
	utils.Certificates_path = "../../../test/nest_ca/certificates/"
	utils.Ca_bin = "../../../test/nest_ca/config/bin/"
	utils.Ca_keys_path = "../../../test/nest_ca/config/keys/"
	csr.Groups = append(csr.Groups, "all")
	csr.Hostname = "lighthouse"
	os.Remove(utils.Certificates_path + csr.Hostname + ".crt")
	csr.Ip = "192.168.100.1/24"
	csr.Rekey = false
	csr.ServerKeygen = false
	b, _ := os.ReadFile("../../../test/lighthouse.pub")
	csr.PublicKey, _, _ = cert.UnmarshalX25519PublicKey(b)
	resp = sendCertificateSign(t, r, endpoint, &csr)
	fmt.Println(resp.Body)
	assert.Equal(t, http.StatusOK, resp.Code)

	//Third test: Reenroll csr success
	csr.Rekey = true
	resp = sendCertificateSign(t, r, endpoint, &csr)
	fmt.Println(resp.Body)
	assert.Equal(t, http.StatusOK, resp.Code)
	//TODO: maybe add Zero knowledge proof for POP
}

func TestGenerateKeys(t *testing.T) {
	var (
		endpoint models.Route = Ca_routes[2]
		err      models.ApiError
		csr      = models.NebulaCsr{}
	)

	r := nest_test.MockRouterForEndpoint(&endpoint)

	//First test: request without csr
	err = models.ApiError{Code: 400, Message: "Bad request: no Nebula Certificate Signing Request provided"}
	errBytes, _ := json.Marshal(err)
	resp := sendCertificateSign(t, r, endpoint, nil)
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Equal(t, errBytes, resp.Body.Bytes())

	//Second test: serverkeygen enroll success
	utils.Certificates_path = "../../../test/nest_ca/certificates/"
	utils.Ca_bin = "../../../test/nest_ca/config/bin/"
	utils.Ca_keys_path = "../../../test/nest_ca/config/keys/"
	csr.Groups = append(csr.Groups, "all")
	csr.Hostname = "lighthouse"
	os.Remove(utils.Certificates_path + csr.Hostname + ".crt")
	csr.Ip = "192.168.100.1/24"
	csr.Rekey = false
	csr.ServerKeygen = true
	b, _ := os.ReadFile("../../../test/lighthouse.pub")
	csr.PublicKey, _, _ = cert.UnmarshalX25519PublicKey(b)
	resp = sendCertificateSign(t, r, endpoint, &csr)
	fmt.Println(resp.Body)
	assert.Equal(t, http.StatusOK, resp.Code)

	//Third test: Reenroll csr success
	csr.Rekey = true
	resp = sendCertificateSign(t, r, endpoint, &csr)
	fmt.Println(resp.Body)
	assert.Equal(t, http.StatusOK, resp.Code)
}
