/*
* Nebula CA service for NEST (Nebula Enrollment over Secure Transport) - OpenAPI 3.0
*
* This is a simple Nebula CA service that signs Nebula Public keys and generates Nebula Key Pairs and Certificates on behalf of the NEST service
*
* API version: 0.2.1
* Contact: gianmarco.decola@studio.unibo.it
 */
package nest_ca

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/m4rkdc/nebula_est/pkg/models"
	"github.com/slackhq/nebula/cert"
)

/*
 * This function gets the Nebula CA certs from the Ca_cert_file and returns them.
 */
func getCaCertFromFile() ([]cert.NebulaCertificate, error) {
	b, err := os.ReadFile(Ca_keys_path + "ca.crt")
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

func Cacerts(c *gin.Context) {
	ca_certs, err := getCaCertFromFile()

	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ApiError{Code: 500, Message: "could not find the Nebula CA certificates: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, ca_certs)
}
