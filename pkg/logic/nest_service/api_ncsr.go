package nest_service

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/m4rkdc/nebula_est/pkg/models"
	"github.com/m4rkdc/nebula_est/pkg/utils"
	"google.golang.org/protobuf/encoding/protojson"
)

// The Sign function returns an HMAC of the given hostname
func sign(hostname string) []byte {
	key, err := os.ReadFile(utils.HMAC_key)
	if err != nil {
		return nil
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(hostname))

	return mac.Sum(nil)
}

// The Verify function verifies if the given secret corresponds to the HMAC of the client hostname
func verify(hostname string, secret []byte) (bool, error) {
	key, err := os.ReadFile(utils.HMAC_key)
	if err != nil {
		return false, &models.ApiError{Code: 500, Message: "Internal server error: " + err.Error()}
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(hostname))

	return hmac.Equal(secret, mac.Sum(nil)), nil
}

// models.Service_routes contains the routes considered by the nest_service router
var Service_routes = [6]models.Route{

	{
		Name:        "Cacerts",
		Method:      "GET",
		Pattern:     "/cacerts",
		HandlerFunc: Cacerts,
	},
	{
		Name:        "NcsrApplication",
		Method:      "POST",
		Pattern:     "/ncsr",
		HandlerFunc: NcsrApplication,
	},
	{
		Name:        "Enroll",
		Method:      "POST",
		Pattern:     "/ncsr/:hostname/enroll",
		HandlerFunc: Enroll,
	},
	{
		Name:        "NcsrStatus",
		Method:      "GET",
		Pattern:     "/ncsr/:hostname",
		HandlerFunc: NcsrStatus,
	},
	{
		Name:        "Reenroll",
		Method:      "POST",
		Pattern:     "/ncsr/:hostname/reenroll",
		HandlerFunc: Reenroll,
	},
	{
		Name:        "Serverkeygen",
		Method:      "POST",
		Pattern:     "/ncsr/:hostname/serverkeygen",
		HandlerFunc: Serverkeygen,
	},
}

// isValideHostname checks if the provided hostname is present in the Hostnames file
func isValidHostname(hostname string) (bool, error) {

	b, err := os.ReadFile(utils.Hostnames_file)
	if err != nil {
		return false, err
	}

	isValid, err := regexp.Match(hostname, b)
	if err != nil {
		return false, err
	}
	return isValid, nil
}

/*
verifyCsr checks that all the fields of the given Nebula Certificate Signing Request are congruent to the request done by the client.
The type of request is discriminated by the option field (i.e., ENROLL, REENROLL, SERVERKEYGEN)
*/
func verifyCsr(csr models.NebulaCsr, hostname string, option int) (int, error) {
	if csr.Hostname != hostname {
		return http.StatusForbidden, &models.ApiError{Code: 403, Message: "Forbidden. The hostname in the URL and the one in the Nebula CSR are different."}
	}
	if option != models.RENROLL && csr.Rekey {
		return http.StatusBadRequest, &models.ApiError{Code: 400, Message: "Bad Request. Rekey is true"}
	}

	switch option {
	case models.ENROLL:
		if csr.ServerKeygen {
			return http.StatusBadRequest, &models.ApiError{Code: 400, Message: "Bad Request. ServerKeygen is true. If you wanted to enroll with a server keygen, please visit https://" + utils.Service_ip + ":" + utils.Service_port + "/" + "/ncsr/" + hostname + "/serverkeygen"}
		}
	case models.SERVERKEYGEN:
		if !csr.ServerKeygen {
			return http.StatusBadRequest, &models.ApiError{Code: 400, Message: "Bad Request. ServerKeygen is false. If you wanted to enroll with a client-generated nebula public key, please visit https://" + utils.Service_ip + ":" + utils.Service_port + "/" + "/ncsr/" + hostname + "/enroll"}
		}
		return 0, nil
	case models.RENROLL:
		if !csr.Rekey || csr.Rekey && csr.ServerKeygen {
			return 0, nil
		}
	}

	if len(csr.PublicKey) == 0 {
		return http.StatusBadRequest, &models.ApiError{Code: 400, Message: "Bad Request. Public key is not provided"}
	}
	/*if len(csr.Pop) == 0 {
		return http.StatusBadRequest, &models.ApiError{Code: 400, Message: "Bad Request. Proof of Possession is not provided"}
	}*/

	return 0, nil
}

/*
getCSRResponse contacts the nest_ca and nest_config services to get the client's Nebula certs and keys, as well as configuration files.
It calls sendCSR and requestConf to do so.
It returns the Nebula CSR Response if both requests are successful, an error otherwise.
*/
func getCSRResponse(hostname string, csr *models.NebulaCsr, option int) (*models.NebulaCsrResponse, error) {
	var conf_resp *models.ConfResponse
	var ca_response *models.CaResponse
	var err error
	if option != models.RENROLL {
		conf_resp, err = requestConf(hostname)
		if err != nil {
			return nil, err
		}
		csr.Groups = conf_resp.Groups
		csr.Ip = conf_resp.Ip
	}

	ca_response, err = sendCSR(csr, option)
	if err != nil {
		return nil, err
	}

	var csr_resp models.NebulaCsrResponse
	csr_resp.NebulaCert = ca_response.NebulaCert
	if option == models.SERVERKEYGEN {
		csr_resp.NebulaPrivateKey = ca_response.NebulaPrivateKey
	}
	if option != models.RENROLL {
		csr_resp.NebulaConf = conf_resp.NebulaConf
		csr_resp.NebulaPath = conf_resp.NebulaPath
	}

	file, err := os.OpenFile(utils.Ncsr_folder+hostname, os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Printf("Could not write to file: %v\n", err)
		return nil, err
	}
	defer file.Close()

	file.WriteString(string(models.COMPLETED) + "\n")
	file.WriteString(ca_response.NebulaCert.Details.NotAfter.String())
	return &csr_resp, nil
}

/*
sendCSR sends the client provide Nebula CSR to the nebula_ca service and returns the nebula_ca generated Nebula certificate to the client.
The Nebula private key is also returned if the option field is SERVERKEYGEN
*/
func sendCSR(csr *models.NebulaCsr, option int) (*models.CaResponse, error) {
	var path string
	switch option {
	case models.ENROLL:
		path = "/ncsr/sign"
	case models.RENROLL:
		if csr.ServerKeygen {
			path = "/ncsr/generate"
		} else {
			path = "/ncsr/sign"
		}
	case models.SERVERKEYGEN:
		path = "/ncsr/generate"
	}

	raw_csr := models.RawNebulaCsr{
		ServerKeygen: &csr.ServerKeygen,
		Rekey:        &csr.Rekey,
		Hostname:     csr.Hostname,
		PublicKey:    csr.PublicKey,
		//Pop:          csr.Pop,
		Groups: csr.Groups,
		Ip:     &csr.Ip,
	}

	b, err := protojson.Marshal(&raw_csr)
	if err != nil {
		return nil, err
	}
	resp, err := http.Post("http://"+utils.Ca_service_ip+":"+utils.Ca_service_port+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}

	b, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var error_response models.ApiError
	if json.Unmarshal(b, &error_response) != nil {
		if error_response.Code == 0 {
			return nil, &error_response
		}
	}
	var response models.CaResponse
	if err = json.Unmarshal(b, &response); err != nil {
		return nil, err
	}

	return &response, nil
}

/*
requestConf sends a request to the nest_config service to generate a Nebula configuration file for the given hostname
It returns the nest_config service response if successful or an error.
*/
func requestConf(hostname string) (*models.ConfResponse, error) {
	resp, err := http.Get("http://" + utils.Conf_service_ip + ":" + utils.Conf_service_port + "/configs/" + hostname)
	if err != nil {
		return nil, err
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var error_response models.ApiError
	if json.Unmarshal(b, &error_response) != nil {
		if error_response.Code == 0 {
			return nil, &error_response
		}
	}
	var response models.ConfResponse
	if err = json.Unmarshal(b, &response); err != nil {
		return nil, err
	}

	return &response, nil
}

/*
The NcsrApplication REST endpoint starts the procedure of enrollment of a NEST client to the system. It authenticates the client to the system before it can continue.
It creates NCSR status file for this client and returns to the client the base url to use for the future actions.
*/
func NcsrApplication(c *gin.Context) {

	var auth = models.NestAuth{}
	if err := c.ShouldBindJSON(&auth); err != nil || len(auth.Hostname) == 0 {
		c.JSON(http.StatusBadRequest, models.ApiError{Code: 400, Message: "Bad request: no client authorization provided"})
		return
	}

	if _, err := os.Stat(utils.Ncsr_folder + auth.Hostname); err == nil {
		c.JSON(http.StatusConflict, models.ApiError{Code: 409, Message: "Conflict. A Nebula CSR for the hostname you provided already exists. If you want to re-enroll, please visit https://" + utils.Service_ip + ":" + utils.Service_port + "/ncsr/" + auth.Hostname + "/reenroll"})
		return
	}

	isValid, err := isValidHostname(auth.Hostname)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ApiError{Code: 500, Message: "Internal server error: " + err.Error()})
		return
	}
	if !isValid {
		c.JSON(http.StatusBadRequest, models.ApiError{Code: 400, Message: "Bad request: The hostname you provided was not found in the Configuration service list"})
		return
	}

	if ok, err := verify(auth.Hostname, auth.Secret); !ok {
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.ApiError{Code: 500, Message: err.Error()})
			return
		}

		c.JSON(http.StatusBadRequest, models.ApiError{Code: 400, Message: "Bad Request. Could not succesfully verify the provided secret"})
		return
	}

	applicationFile, err := os.OpenFile(utils.Ncsr_folder+auth.Hostname, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ApiError{Code: 500, Message: "Internal server error: " + err.Error()})
		return
	}
	if _, err = applicationFile.WriteString(string(models.PENDING)); err != nil {
		c.JSON(http.StatusInternalServerError, models.ApiError{Code: 500, Message: "Internal server error: " + err.Error()})
		return
	}

	c.Header("Location", "http://"+utils.Service_ip+":"+utils.Service_port+"/ncsr/"+auth.Hostname)
	c.Status(http.StatusCreated)
}

// NcsrStatus REST endpoint returns the state of the enrollment request by the client specified by the hostname parameter (PENDING, COMPLETED, EXPIRED)
func NcsrStatus(c *gin.Context) {
	hostname := c.Param("hostname")
	if len(strings.TrimSpace(hostname)) == 0 {
		c.JSON(http.StatusBadRequest, models.ApiError{Code: 400, Message: "Bad request: no hostname provided"})
		return
	}

	fmt.Println("Nebula CSR Status request received for hostname: " + hostname)

	file, err := os.OpenFile(utils.Ncsr_folder+hostname, os.O_RDWR|os.O_TRUNC, 0600)
	if err != nil {
		c.JSON(http.StatusNotFound, models.ApiError{Code: 404, Message: "Not found. Could not find an open Nebula CSR application for the specified hostname. If you want to enroll, provide your hostname to http:" + utils.Service_ip + ":" + utils.Service_port + "/ncsr"})
		return
	}
	defer file.Close()

	fileScanner := bufio.NewScanner(file)

	fileScanner.Split(bufio.ScanLines)
	var fileLines []string
	for fileScanner.Scan() {
		fileLines = append(fileLines, fileScanner.Text())
	}

	if len(fileLines) == 2 {
		notAfter, err := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", fileLines[1])
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.ApiError{Code: 500, Message: "Internal server error: " + err.Error()})
			return
		}
		if time.Until(notAfter) < 0 {
			fileLines[0] = string(models.EXPIRED)
			for _, s := range fileLines {
				file.WriteString(s + "\n")
			}
		}
	}
	c.JSON(http.StatusOK, fileLines[0])
}

/*
The Enroll REST endpoint performs the actual enrollment of the client to the system and ends with the client being provided its Nebula certificate and configuration file.
The NCSR status file will also be modified to COMPLETED.
*/
func Enroll(c *gin.Context) {
	hostname := c.Param("hostname")
	if len(strings.TrimSpace(hostname)) == 0 {
		c.JSON(http.StatusBadRequest, models.ApiError{Code: 400, Message: "Bad request: no hostname provided"})
		return
	}
	b, err := os.ReadFile(utils.Ncsr_folder + hostname)
	if err != nil {
		c.JSON(http.StatusUnauthorized, models.ApiError{Code: 401, Message: "Unhautorized: please authenticate yourself to https://" + utils.Service_ip + ":" + utils.Service_port + "/ncsr providing your hostname and secret, before accessing this endpoint"})
		return
	}

	if isPending, _ := regexp.Match(string(models.PENDING), b); !isPending {
		c.JSON(http.StatusConflict, models.ApiError{Code: 409, Message: "Conflict. This hostname has already enrolled. If you want to re-enroll, please visit https://" + utils.Service_ip + ":" + utils.Service_port + "/ncsr/" + hostname + "/reenroll"})
		return
	}

	var csr models.NebulaCsr

	if err := c.ShouldBindJSON(&csr); err != nil {
		c.JSON(http.StatusBadRequest, models.ApiError{Code: 400, Message: "Bad request: no Nebula Certificate Signing Request provided"})
		return
	}

	status_code, api_error := verifyCsr(csr, hostname, models.ENROLL)
	if api_error != nil {
		c.JSON(status_code, api_error)
		return
	}

	csr_resp, err := getCSRResponse(hostname, &csr, models.ENROLL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ApiError{Code: 500, Message: "Internal Server Error: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, csr_resp)
}

/*
The Reenroll REST endpoint performs the renrollment of a previuosly enrolled client.
The enpoint is unique to both serverkeygen ans simple reenrollment. One can discriminate between the two request modes by inspecting the serverkeygen field of the client Nebula CSR
The process can be initiated if the client's keys have been compromised and there is the need to update them (rekey field of the NCSR) or if the previous client certificate has expired.
It ends with the client being provided its new Nebula certificate.
The NCSR status file will also be modified to COMPLETED.
*/
func Reenroll(c *gin.Context) {
	hostname := c.Param("hostname")
	if len(strings.TrimSpace(hostname)) == 0 {
		c.JSON(http.StatusBadRequest, models.ApiError{Code: 400, Message: "Bad request: no hostname provided"})
		return
	}

	b, err := os.ReadFile(utils.Ncsr_folder + hostname)
	if err != nil {
		c.JSON(http.StatusUnauthorized, models.ApiError{Code: 401, Message: "Unhautorized: please authenticate yourself to https://" + utils.Service_ip + ":" + utils.Service_port + "/ncsr providing your hostname and secret, before accessing this endpoint"})
		return
	}

	if isPending, _ := regexp.Match(string(models.PENDING), b); isPending {
		c.JSON(http.StatusConflict, models.ApiError{Code: 409, Message: "Conflict. This hostname has not yet finished enrolling. If you want to do so, please visit https://" + utils.Service_ip + ":" + utils.Service_port + "/ncsr/" + hostname + "/enroll"})
		return
	}

	var csr models.NebulaCsr

	if err := c.ShouldBindJSON(&csr); err != nil {
		c.JSON(http.StatusBadRequest, models.ApiError{Code: 400, Message: "Bad request: no Nebula Certificate Signing Request provided"})
		return
	}

	status_code, api_error := verifyCsr(csr, hostname, models.RENROLL)
	if api_error != nil {
		c.JSON(status_code, api_error)
		return
	}

	csr_resp, err := getCSRResponse(hostname, &csr, models.RENROLL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ApiError{Code: 500, Message: "Internal Server Error: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, csr_resp)
}

/*
The Serverkeygen REST enpoint performs the enrollment of a client to the system by requesting the nest_ca to generate the Nebula key pairs in stead of the client.
The function return conditions are the same as the Enroll endpoint
*/
func Serverkeygen(c *gin.Context) {
	hostname := c.Param("hostname")
	if len(strings.TrimSpace(hostname)) == 0 {
		c.JSON(http.StatusBadRequest, models.ApiError{Code: 400, Message: "Bad request: no hostname provided"})
		return
	}
	b, err := os.ReadFile(utils.Ncsr_folder + hostname)
	if err != nil {
		c.JSON(http.StatusUnauthorized, models.ApiError{Code: 401, Message: "Unhautorized: please authenticate yourself to https://" + utils.Service_ip + ":" + utils.Service_port + "/ncsr providing your hostname and secret, before accessing this endpoint"})
		return
	}

	if isPending, _ := regexp.Match(string(models.PENDING), b); !isPending {
		c.JSON(http.StatusConflict, models.ApiError{Code: 409, Message: "Conflict. This hostname has already enrolled. If you want to re-enroll, please visit https:https://" + utils.Service_ip + ":" + utils.Service_port + "/ncsr/" + hostname + "/reenroll"})
		return
	}

	var csr models.NebulaCsr

	if err := c.ShouldBindJSON(&csr); err != nil {
		c.JSON(http.StatusBadRequest, models.ApiError{Code: 400, Message: "Bad request: no Nebula Certificate Signing Request provided"})
		return
	}

	status_code, api_error := verifyCsr(csr, hostname, models.SERVERKEYGEN)
	if api_error != nil {
		c.JSON(status_code, api_error)
		return
	}

	csr_resp, err := getCSRResponse(hostname, &csr, models.SERVERKEYGEN)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ApiError{Code: 500, Message: "Internal Server Error: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, csr_resp)
}
