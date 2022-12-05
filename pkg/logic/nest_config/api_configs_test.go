package nest_config

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/assert/v2"
	"github.com/m4rkdc/nebula_est/pkg/models"
	"github.com/m4rkdc/nebula_est/pkg/utils"
	nest_test "github.com/m4rkdc/nebula_est/test"
)

func sendGetConfig(t *testing.T, r *gin.Engine, endpoint models.Route, hostname string) *httptest.ResponseRecorder {
	var req *http.Request
	url := strings.ReplaceAll(endpoint.Pattern, ":hostname", hostname)
	req, _ = http.NewRequest(endpoint.Method, url, http.NoBody)
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	return resp
}

func TestGetConfig(t *testing.T) {
	var (
		endpoint  models.Route = Conf_routes[1]
		err       models.ApiError
		hostname  string
		conf_resp models.ConfResponse
	)

	r := nest_test.MockRouterForEndpoint(&endpoint)

	//First test: empty hostname
	hostname = " "
	err = models.ApiError{Code: 400, Message: "Bad request: no hostname provided"}
	errBytes, _ := json.Marshal(err)
	resp := sendGetConfig(t, r, endpoint, hostname)
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Equal(t, errBytes, resp.Body.Bytes())

	//Second test: cannot find generated config files
	hostname = "lighthouse"
	resp = sendGetConfig(t, r, endpoint, hostname)
	assert.Equal(t, http.StatusInternalServerError, resp.Code)

	//Third test: success
	utils.Dhall_dir = "../../../test/nest_config/dhall/"
	utils.Dhall_configuration = utils.Dhall_dir + "nebula/nebula_conf.dhall"
	resp = sendGetConfig(t, r, endpoint, hostname)
	assert.Equal(t, http.StatusOK, resp.Code)

	conf_resp.Ip = "192.168.100.1/24"
	conf_resp.NebulaPath = "/etc/nebula/"
	conf_resp.Groups = append(conf_resp.Groups, "all")
	b, _ := os.ReadFile(utils.Dhall_dir + "nebula/generated/" + hostname + ".yaml")
	conf_resp.NebulaConf = b
	conf_resp_bytes, _ := json.Marshal(conf_resp)
	fmt.Println(conf_resp)
	fmt.Println(resp.Body)
	assert.Equal(t, conf_resp_bytes, resp.Body.Bytes())
}

/*func TestVerify(t *testing.T) {}*/
