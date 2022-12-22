package nest_ca

import (
	"bytes"
	"encoding/json"
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
	"google.golang.org/protobuf/encoding/protojson"
)

func sendCertificateSign(t *testing.T, r *gin.Engine, endpoint models.Route, csr *models.NebulaCsr) *httptest.ResponseRecorder {
	var req *http.Request
	if csr == nil {
		req, _ = http.NewRequest(endpoint.Method, endpoint.Pattern, http.NoBody)
	} else {
		raw_csr := models.RawNebulaCsr{
			ServerKeygen: &csr.ServerKeygen,
			Rekey:        &csr.Rekey,
			Hostname:     csr.Hostname,
			PublicKey:    csr.PublicKey,
			Groups:       csr.Groups,
			Ip:           &csr.Ip,
		}
		csr_bytes, _ := protojson.Marshal(&raw_csr)
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
	utils.Certificates_path = "../../test/certificates/"
	utils.Ca_bin = "../../test/config/bin/nebula-cert"
	utils.Ca_keys_path = "../../test/config/keys/"
	csr.Groups = append(csr.Groups, "all")
	csr.Hostname = "lighthouse"
	os.Remove(utils.Certificates_path + csr.Hostname + ".crt")
	csr.Ip = "192.168.100.1/24"
	csr.Rekey = false
	csr.ServerKeygen = false
	b, _ := os.ReadFile("../../test/lighthouse.pub")
	csr.PublicKey, _, _ = cert.UnmarshalX25519PublicKey(b)
	resp = sendCertificateSign(t, r, endpoint, &csr)
	assert.Equal(t, http.StatusOK, resp.Code)

	//Third test: reenroll with rekey but same public key
	csr.Ip = ""
	err = models.ApiError{Code: 400, Message: "Bad request: the provided public key is already used by an already enrolled host"}
	errBytes, _ = json.Marshal(err)

	resp = sendCertificateSign(t, r, endpoint, &csr)
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Equal(t, errBytes, resp.Body.Bytes())

	//Fourth test: Reenroll csr success
	csr.Rekey = true
	b, _ = os.ReadFile("../../test/lightouse2.pub")
	csr.PublicKey, _, _ = cert.UnmarshalX25519PublicKey(b)

	resp = sendCertificateSign(t, r, endpoint, &csr)
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
	utils.Certificates_path = "../../test/certificates/"
	utils.Ca_bin = "../../test/config/bin/nebula-cert"
	utils.Ca_keys_path = "../../test/config/keys/"
	csr.Groups = append(csr.Groups, "all")
	csr.Hostname = "lighthouse"
	os.Remove(utils.Certificates_path + csr.Hostname + ".crt")
	csr.Ip = "192.168.100.1/24"
	csr.Rekey = false
	csr.ServerKeygen = true
	b, _ := os.ReadFile("../../test/lighthouse.pub")
	csr.PublicKey, _, _ = cert.UnmarshalX25519PublicKey(b)
	resp = sendCertificateSign(t, r, endpoint, &csr)
	assert.Equal(t, http.StatusOK, resp.Code)

	//Third test: Reenroll csr success
	csr.Rekey = true
	csr.Ip = ""
	resp = sendCertificateSign(t, r, endpoint, &csr)
	assert.Equal(t, http.StatusOK, resp.Code)
}
