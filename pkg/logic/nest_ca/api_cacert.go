/*
 * NEST: Nebula Enrollment over Secure Transport - OpenAPI 3.0
 *
 * This package contains the NEST_CA service routes and their REST API endpoints implementation, along with some service-specific utilities.
 * API version: 0.3.1
 * Contact: gianmarco.decola@studio.unibo.it
 */
package nest_ca

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/m4rkdc/nebula_est/pkg/models"
	"github.com/m4rkdc/nebula_est/pkg/utils"
	"github.com/slackhq/nebula/cert"
)

// The getCaCertFomFile function gets the Nebula CA certs from the Ca_cert_file and returns them.
func getCaCertFromFile() ([]cert.NebulaCertificate, error) {
	b, err := os.ReadFile(utils.Ca_keys_path + "ca.crt")
	if err != nil {
		return nil, err
	}

	var ca_certs []cert.NebulaCertificate
	for {
		cert, b, err := cert.UnmarshalNebulaCertificateFromPEM(b)
		if err != nil {
			return nil, err
		}
		if cert == nil {
			break
		}
		ca_certs = append(ca_certs, *cert)
		if len(b) == 0 {
			break
		}
	}

	return ca_certs, nil
}

// The Cacerts REST endpoint returns the Nebula CA(s) certificates to the nest_service
func Cacerts(c *gin.Context) {
	ca_certs, err := getCaCertFromFile()

	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ApiError{Code: 500, Message: "could not find the Nebula CA certificates: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, ca_certs)
}
