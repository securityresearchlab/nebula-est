package nest_service

import (
	"encoding/json"
	"io"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/m4rkdc/nebula_est/nest_service/pkg/models"
	"github.com/m4rkdc/nebula_est/nest_service/pkg/utils"
	"github.com/slackhq/nebula/cert"
)

/*
The GetCaCerts function sends a request to the Nebula CA service for the Nebula CA certificates.
The function retries to send the request after waiting Retry-After seconds
*/
func getCaCerts() ([]cert.NebulaCertificate, error) {
	//TODO: add retry
	resp, err := http.Get("http://" + utils.Ca_service_ip + ":" + utils.Ca_service_port + "/cacerts")
	if err != nil {
		return nil, err
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var error_response *models.ApiError
	if json.Unmarshal(b, error_response) != nil {
		return nil, error_response
	}
	var response []cert.NebulaCertificate
	err = json.Unmarshal(b, &response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// This function gets the Nebula CA certs from the Ca_cert_file and returns them.
func getCaCertFromFile() ([]cert.NebulaCertificate, error) {
	b, err := os.ReadFile(utils.Ca_cert_file)
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

/*
The CheckCaCertFile function checks if the nest.Ca_cert_file exists.
If not, sends a request to the CA service and creates it by filling it with the returned Nebula CA certificates.
*/
func CheckCaCertFile() error {
	if _, err := os.Stat(utils.Ca_cert_file); err != nil {
		ca_certs, err := getCaCerts()
		if err != nil {
			return err
		}

		for _, nc := range ca_certs {
			b, err := nc.MarshalToPEM()
			if err != nil {
				return err
			}

			if err = os.WriteFile(utils.Ca_cert_file, b, 0600); err != nil {
				return err
			}
		}
	}
	return nil
}

/*
The Cacerts REST endpoint contacts the nest_ca service to get the Nebula CA(s) certificate(s).
It returns an array of cert.NebulaCertificate to the client.
*/
func Cacerts(c *gin.Context) {
	/*if err := CheckCaCertFile(); err != nil {
		c.JSON(http.StatusInternalServerError, models.ApiError{Code: 500, Message: "Internal server error: " + err.Error()})
		return
	}*/
	ca_certs, err := getCaCertFromFile()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ApiError{Code: 500, Message: "Internal server error: " + err.Error()})
	}

	c.JSON(http.StatusOK, ca_certs)
}