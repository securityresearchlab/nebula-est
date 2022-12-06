package nest_service

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-playground/assert/v2"
	"github.com/m4rkdc/nebula_est/nest_service/pkg/utils"
	nest_test "github.com/m4rkdc/nebula_est/nest_service/test"
)

func TestCacerts(t *testing.T) {
	var endpoint = Service_routes[0]
	r := nest_test.MockRouterForEndpoint(&endpoint)
	utils.Ca_cert_file = "../../../test/nest_service/config/ca.crt"
	certs, _ := getCaCertFromFile()
	reqOk, _ := http.NewRequest(endpoint.Method, endpoint.Pattern, nil)
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, reqOk)
	assert.Equal(t, http.StatusOK, resp.Code)
	certsBytes, _ := json.Marshal(certs)
	assert.Equal(t, certsBytes, resp.Body.Bytes())

	utils.Ca_cert_file = "./"
	reqError, _ := http.NewRequest(endpoint.Method, endpoint.Pattern, nil)
	resp = httptest.NewRecorder()
	r.ServeHTTP(resp, reqError)
	assert.Equal(t, http.StatusInternalServerError, resp.Code)

}
