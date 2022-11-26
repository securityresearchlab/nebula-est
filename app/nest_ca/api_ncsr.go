/*
 * NEST: Nebula Enrollment over Secure Transport - OpenAPI 3.0
 *
 * This package contains the NEST_CA service routes and their REST API endpoints implementation, along with some service-specific utilities.
 * API version: 0.3.1
 * Contact: gianmarco.decola@studio.unibo.it
 */
package nest_ca

import (
	"crypto/ed25519"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/m4rkdc/nebula_est/pkg/models"
	"github.com/slackhq/nebula/cert"
	"google.golang.org/protobuf/proto"
)

// the checkExistingCert function verifies if the given hostname has already an issued certificate. If so, returns the containing IPAddress.
func checkExistingCert(hostname string) (string, error) {
	b, err := os.ReadFile(Certificates_path + hostname + ".crt")
	if err != nil {
		return "", &models.ApiError{Code: 500, Message: "Internal server error: " + err.Error()}
	}

	nc, _, err := cert.UnmarshalNebulaCertificateFromPEM(b)
	if err != nil {
		return "", &models.ApiError{Code: 500, Message: "Internal server error: " + err.Error()}
	}

	err = os.Remove(Certificates_path + hostname + ".crt")
	if err != nil {
		return "", &models.ApiError{Code: 500, Message: "Internal server error: " + err.Error()}
	}
	return nc.Details.Ips[0].IP.String(), nil
}

/*
 * The generateCertificate function creates a new Nebula certificate for the given Nebula CSR.
 * To do so, it either signs the client-provided public key or generates the Nebula key pair and then signs it depending on the option discriminator (ENROLL, SERVERKEYGEN))
 */
func generateCertificate(csr *models.NebulaCsr, option int) (*models.CaResponse, error) {
	var ca_response *models.CaResponse
	var groups string
	var ip string
	for _, s := range csr.Groups {
		groups += s + ","
	}

	ip, err := checkExistingCert(csr.Hostname)
	if err != nil {
		return nil, &models.ApiError{Code: http.StatusInternalServerError, Message: "Internal server error: " + err.Error()}
	}
	if len(ip) == 0 {
		if strings.Contains(csr.Hostname, "lightouse") {
			ip = Network.nebula_network.First().String()
		} else {
			ip = Network.AddIpNetwork().String()
		}
	}
	var cmd *exec.Cmd
	if option == models.SERVERKEYGEN {
		cmd = exec.Command(Ca_bin, "keygen -out-pub "+Certificates_path+csr.Hostname+".pub -out-key "+Certificates_path+csr.Hostname+".key")
		if err = cmd.Run(); err != nil {
			return nil, &models.ApiError{Code: 500, Message: "Internal server error: " + err.Error()}
		}
		b, err := os.ReadFile(Certificates_path + csr.Hostname + ".key")
		if err != nil {
			return nil, &models.ApiError{Code: 500, Message: "Internal server error: " + err.Error()}
		}
		err = os.Remove(Certificates_path + csr.Hostname + ".key")
		if err != nil {
			return nil, &models.ApiError{Code: 500, Message: "Internal server error: " + err.Error()}
		}

		key, _, err := cert.UnmarshalX25519PrivateKey(b)
		if err != nil {
			return nil, &models.ApiError{Code: 500, Message: "Internal server error: " + err.Error()}
		}
		ca_response.NebulaPrivateKey = key
	}

	cmd = exec.Command(Ca_bin, "sign -ca-crt "+Ca_keys_path+"ca.crt -ca-key "+Ca_keys_path+"ca.key -in-pub "+Certificates_path+csr.Hostname+".pub -groups "+groups[:len(groups)-1]+" -name "+csr.Hostname+" -out-crt "+Certificates_path+csr.Hostname+".crt -ip "+ip+"/"+strconv.Itoa(Network.GetIpNetwork().Mask()))
	if err = cmd.Run(); err != nil {
		return nil, &models.ApiError{Code: 500, Message: "Internal server error: " + err.Error()}
	}

	if err = os.Remove(Certificates_path + csr.Hostname + ".pub"); err != nil {
		return nil, &models.ApiError{Code: 500, Message: "Internal server error: " + err.Error()}
	}

	b, err := os.ReadFile(Certificates_path + csr.Hostname + ".crt")
	if err != nil {
		return nil, &models.ApiError{Code: 500, Message: "Internal server error: " + err.Error()}
	}

	nc, _, err := cert.UnmarshalNebulaCertificateFromPEM(b)
	if err != nil {
		return nil, &models.ApiError{Code: 500, Message: "Internal server error: " + err.Error()}
	}
	ca_response.NebulaCert = *nc

	return ca_response, nil
}

/*
 * The CertificateSign REST endpoint creates a new Nebula certificate by signing the client provided Nebula Public Key.
 * It verifies if the provided Proof of Possession is valid for the given Public key before returning the certificate back to the client.
 */
func CertificateSign(c *gin.Context) {
	fmt.Println("Certificate Signing Request arrived")
	var csr models.NebulaCsr

	if err := c.ShouldBindJSON(&csr); err != nil {
		c.JSON(http.StatusBadRequest, models.ApiError{Code: 400, Message: "Bad request: no Nebula Certificate Signing Request provided"})
		return
	}

	var csr_ver = models.RawNebulaCsr{
		ServerKeygen: &csr.ServerKeygen,
		Rekey:        &csr.Rekey,
		Hostname:     csr.Hostname,
		PublicKey:    csr.PublicKey,
	}

	b, err := proto.Marshal(&csr_ver)

	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ApiError{Code: 500, Message: "Internal server error: " + err.Error()})
		return
	}

	if !ed25519.Verify(csr.PublicKey, b, csr.Pop) {
		c.JSON(http.StatusBadRequest, models.ApiError{Code: 400, Message: "Bad Request. Proof of Possession is not valid"})
		return
	}

	if err = os.WriteFile(Certificates_path+csr.Hostname+".pub", csr.PublicKey, 0600); err != nil {
		c.JSON(http.StatusInternalServerError, models.ApiError{Code: 500, Message: err.Error()})
		return
	}

	ca_response, err := generateCertificate(&csr, models.ENROLL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, *ca_response)
}

// The GenerateKeys REST endpoint creates a new Nebula certificate by generating the Nebula private key and certificate for the given hostname.
func GenerateKeys(c *gin.Context) {
	fmt.Println("Certificate Signing Request arrived")

	var csr models.NebulaCsr

	if err := c.ShouldBindJSON(&csr); err != nil {
		c.JSON(http.StatusBadRequest, models.ApiError{Code: 400, Message: "Bad request: no Nebula Certificate Signing Request provided"})
		return
	}

	ca_response, err := generateCertificate(&csr, models.ENROLL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, *ca_response)
}
