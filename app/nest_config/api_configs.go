package conf

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/m4rkdc/nebula_est/pkg/models"
	dhall "github.com/philandstuff/dhall-golang/v6"
)

/*
The GetConfig REST endpoint reads the already generated Nebula config file for the given hostname and returns it.
The ConfResponse also contains the path in which all the keys and configs have to be installed on the client and the IP and Security groups of the client
*/
func GetConfig(c *gin.Context) {
	var (
		conf_resp      models.ConfResponse
		nebula_host    models.NebulaHost
		nebula_network models.NebulaNetwork
		groups         []string
	)
	hostname := c.Params.ByName("hostname")
	if hostname == "" {
		c.JSON(http.StatusBadRequest, models.ApiError{Code: 400, Message: "Bad request: no hostname provided"})
		return
	}

	b, err := os.ReadFile(Dhall_dir + "nebula/generated/" + hostname + ".yaml")
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ApiError{Code: 500, Message: "Internal Server Error: " + err.Error()})
		return
	}
	conf_resp.NebulaConf = b
	err = dhall.UnmarshalFile(Dhall_dir+"nebula/hosts/"+hostname+".dhall", &nebula_host)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ApiError{Code: 500, Message: "Internal Server Error: " + err.Error()})
		return
	}
	err = dhall.UnmarshalFile(Dhall_configuration, &nebula_network)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ApiError{Code: 500, Message: "Internal Server Error: " + err.Error()})
		return
	}

	conf_resp.Ip = fmt.Sprint(nebula_host.Ip.I1) + "." + fmt.Sprint(nebula_host.Ip.I2) + "." + fmt.Sprint(nebula_host.Ip.I3) + "." + fmt.Sprint(nebula_host.Ip.I4) + fmt.Sprint(nebula_network.IpMask)
	for _, g := range nebula_network.Groups {
		for _, h := range g.Group_hosts {
			if h.Name.Name == hostname {
				groups = append(groups, string(g.Group_name))
			}
		}
	}
	conf_resp.Groups = groups
	conf_resp.NebulaPath = strings.TrimSuffix(nebula_host.Pki.Key, hostname+".key")

	c.JSON(http.StatusOK, conf_resp)
}

/*
func ValidateCertificate(c *gin.Context) {

}
*/
