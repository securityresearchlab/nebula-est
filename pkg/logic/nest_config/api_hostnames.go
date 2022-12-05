package nest_config

import (
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/m4rkdc/nebula_est/pkg/models"
	"github.com/m4rkdc/nebula_est/pkg/utils"
)

// The GetValidHostnames REST endpoint inspects the dhall configuration file for the expected valid hostnames for the future Nebula network and returns them
func GetValidHostnames(c *gin.Context) {
	dir, err := os.ReadDir(utils.Dhall_dir + "nebula/hosts/")
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ApiError{Code: 500, Message: "Internal Server Error. Ther was an error reading the Dhall configuration files"})
		return
	}

	var hostnames []string
	for _, d := range dir {
		hostnames = append(hostnames, strings.TrimSuffix(d.Name(), ".dhall"))
	}
	c.JSON(http.StatusOK, hostnames)
}
