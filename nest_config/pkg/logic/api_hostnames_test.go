package nest_config

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/go-playground/assert/v2"
	"github.com/m4rkdc/nebula_est/nest_service/pkg/utils"
	nest_test "github.com/m4rkdc/nebula_est/nest_service/test"
)

func TestGetValidHostnames(t *testing.T) {
	utils.Dhall_dir = "./"
	var endpoint = Conf_routes[0]
	r := nest_test.MockRouterForEndpoint(&endpoint)
	reqError, _ := http.NewRequest(endpoint.Method, endpoint.Pattern, nil)
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, reqError)
	assert.Equal(t, http.StatusInternalServerError, resp.Code)

	utils.Dhall_dir = "../../../configs/nest_config/dhall/"
	reqOk, _ := http.NewRequest(endpoint.Method, endpoint.Pattern, nil)
	resp = httptest.NewRecorder()
	r.ServeHTTP(resp, reqOk)
	assert.Equal(t, http.StatusOK, resp.Code)
	var hostnames []string
	dir, _ := os.ReadDir(utils.Dhall_dir + "nebula/hosts/")
	for _, d := range dir {
		hostnames = append(hostnames, strings.TrimSuffix(d.Name(), ".dhall"))
	}
	var testHostnames []string
	json.Unmarshal(resp.Body.Bytes(), &testHostnames)
	assert.Equal(t, hostnames, testHostnames)
}
