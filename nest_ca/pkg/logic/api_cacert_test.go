package nest_ca

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
	var endpoint = Ca_routes[0]
	r := nest_test.MockRouterForEndpoint(&endpoint)

	//First test: cannot find the ca.crt file
	utils.Ca_keys_path = "./"
	reqError, _ := http.NewRequest(endpoint.Method, endpoint.Pattern, nil)
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, reqError)
	assert.Equal(t, http.StatusInternalServerError, resp.Code)

	//Second test: success
	utils.Ca_keys_path = "../../../test/nest_ca/config/keys/"
	certs, _ := getCaCertFromFile()
	reqOk, _ := http.NewRequest(endpoint.Method, endpoint.Pattern, nil)
	resp = httptest.NewRecorder()
	r.ServeHTTP(resp, reqOk)
	assert.Equal(t, http.StatusOK, resp.Code)
	certsBytes, _ := json.Marshal(certs)
	assert.Equal(t, certsBytes, resp.Body.Bytes())
}
