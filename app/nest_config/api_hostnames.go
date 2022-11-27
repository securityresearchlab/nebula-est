package conf

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/m4rkdc/nebula_est/pkg/models"
	dhall "github.com/philandstuff/dhall-golang/v6"
)

// The GetValidHostnames REST endpoint inspects the dhall configuration file for the expected valid hostnames for the future Nebula network and returns them
func GetValidHostnames(c *gin.Context) {
	var nebula_network models.NebulaNetwork
	err := dhall.UnmarshalFile(Dhall_configuration, &nebula_network)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ApiError{Code: 500, Message: "Internal Server Error. Ther was an error reading the Dhall configuration files"})
		return
	}

	var hostnames []string
	for _, h := range nebula_network.Hosts {
		hostnames = append(hostnames, h.Name.Name)
	}
	c.JSON(http.StatusOK, hostnames)
}
