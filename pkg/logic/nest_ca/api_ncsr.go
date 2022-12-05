/*
 * NEST: Nebula Enrollment over Secure Transport - OpenAPI 3.0
 *
 * This package contains the NEST_CA service routes and their REST API endpoints implementation, along with some service-specific utilities.
 * API version: 0.3.1
 * Contact: gianmarco.decola@studio.unibo.it
 */
package nest_ca

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"

	"github.com/gin-gonic/gin"
	"github.com/m4rkdc/nebula_est/pkg/models"
	"github.com/m4rkdc/nebula_est/pkg/utils"
	"github.com/slackhq/nebula/cert"
)

var Ca_routes = [3]models.Route{
	{
		Name:        "Cacerts",
		Method:      "GET",
		Pattern:     "/cacerts",
		HandlerFunc: Cacerts,
	},
	{
		Name:        "CertificateSign",
		Method:      "POST",
		Pattern:     "/ncsr/sign",
		HandlerFunc: CertificateSign,
	},
	{
		Name:        "GenerateKeys",
		Method:      "POST",
		Pattern:     "/ncsr/generate",
		HandlerFunc: GenerateKeys,
	},
}

// the readExistingCert function verifies if the given hostname has already an issued certificate. If so, fills the empty fields of its Nebula CSR.
func readExistingCert(csr *models.NebulaCsr) error {
	b, err := os.ReadFile(utils.Certificates_path + csr.Hostname + ".crt")
	if err != nil {
		return &models.ApiError{Code: 500, Message: "Internal server error: " + err.Error()}
	}

	nc, _, err := cert.UnmarshalNebulaCertificateFromPEM(b)
	if err != nil {
		return &models.ApiError{Code: 500, Message: "Internal server error: " + err.Error()}
	}

	err = os.Remove(utils.Certificates_path + csr.Hostname + ".crt")
	if err != nil {
		return &models.ApiError{Code: 500, Message: "Internal server error: " + err.Error()}
	}

	csr.Groups = nc.Details.Groups
	csr.Ip = nc.Details.Ips[0].String()
	fmt.Println("IP: " + csr.Ip)
	csr.PublicKey = nc.Details.PublicKey

	return nil
}

/*
 * The generateCertificate function creates a new Nebula certificate for the given Nebula CSR.
 * To do so, it either signs the client-provided public key or generates the Nebula key pair and then signs it depending on the option discriminator (ENROLL, SERVERKEYGEN))
 */
func generateCertificate(csr *models.NebulaCsr, option int) (*models.CaResponse, error) {
	var (
		ca_response = &models.CaResponse{}
		groups      string
		ip          string
		err         error
	)
	for _, s := range csr.Groups {
		groups += s + ","
	}

	ip = csr.Ip
	if option == models.SERVERKEYGEN {
		out, err := exec.Command(utils.Ca_bin+"nebula-cert", "keygen", "-out-pub", utils.Certificates_path+csr.Hostname+".pub", "-out-key", utils.Certificates_path+csr.Hostname+".key").CombinedOutput()
		if err != nil {
			return nil, &models.ApiError{Code: 500, Message: "Internal server error: " + err.Error() + string(out)}
		}
		b, err := os.ReadFile(utils.Certificates_path + csr.Hostname + ".key")
		if err != nil {
			return nil, &models.ApiError{Code: 500, Message: "Internal server error: " + err.Error()}
		}
		err = os.Remove(utils.Certificates_path + csr.Hostname + ".key")
		if err != nil {
			return nil, &models.ApiError{Code: 500, Message: "Internal server error: " + err.Error()}
		}

		key, _, err := cert.UnmarshalX25519PrivateKey(b)
		if err != nil {
			return nil, &models.ApiError{Code: 500, Message: "Internal server error: " + err.Error()}
		}
		ca_response.NebulaPrivateKey = key
	}

	out, err := exec.Command(utils.Ca_bin+"nebula-cert", "sign", "-ca-crt", utils.Ca_keys_path+"ca.crt", "-ca-key", utils.Ca_keys_path+"ca.key", "-in-pub", utils.Certificates_path+csr.Hostname+".pub", "-groups", groups[:len(groups)-1], "-name", csr.Hostname, "-out-crt", utils.Certificates_path+csr.Hostname+".crt", "-ip", ip).CombinedOutput()
	if err != nil {
		return nil, &models.ApiError{Code: 500, Message: "Internal server error: " + err.Error() + string(out)}
	}

	if err = os.Remove(utils.Certificates_path + csr.Hostname + ".pub"); err != nil {
		return nil, &models.ApiError{Code: 500, Message: "Internal server error: " + err.Error()}
	}

	b, err := os.ReadFile(utils.Certificates_path + csr.Hostname + ".crt")
	if err != nil {
		return nil, &models.ApiError{Code: 500, Message: "Internal server error: " + err.Error()}
	}

	nc, _, err := cert.UnmarshalNebulaCertificateFromPEM(b)
	if err != nil {
		return nil, &models.ApiError{Code: 500, Message: "Internal server error: " + err.Error()}
	}
	ca_response.NebulaCert = *nc.Copy()

	//TODO: POST request to Verify endpoint of the nest_config service to see if the generated certificate is coeherent with the network

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
	/* TODO: maybe replace with a Schnorr proof of knwoledge
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
	*/
	if csr.Rekey {
		if err := readExistingCert(&csr); err != nil {
			c.JSON(http.StatusInternalServerError, models.ApiError{Code: 500, Message: err.Error()})
			return
		}
	}

	if err := os.WriteFile(utils.Certificates_path+csr.Hostname+".pub", cert.MarshalX25519PublicKey(csr.PublicKey), 0600); err != nil {
		c.JSON(http.StatusInternalServerError, models.ApiError{Code: 500, Message: err.Error()})
		return
	}

	ca_response, err := generateCertificate(&csr, models.ENROLL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, err.Error())
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

	if csr.Rekey {
		if err := readExistingCert(&csr); err != nil {
			c.JSON(http.StatusInternalServerError, models.ApiError{Code: 500, Message: err.Error()})
			return
		}
	}

	ca_response, err := generateCertificate(&csr, models.SERVERKEYGEN)
	if err != nil {
		c.JSON(http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, *ca_response)
}
