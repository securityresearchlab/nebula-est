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
	"reflect"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/m4rkdc/nebula_est/nest_service/pkg/models"
	"github.com/m4rkdc/nebula_est/nest_service/pkg/utils"
	"github.com/slackhq/nebula/cert"
	"google.golang.org/protobuf/proto"
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

func checkPublicKey(publicKey []byte) bool {
	certificates, _ := os.ReadDir(utils.Certificates_path)
	for _, f := range certificates {
		if strings.HasSuffix(f.Name(), ".crt") {
			b, _ := os.ReadFile(utils.Certificates_path + f.Name())
			fmt.Println(publicKey)

			nc, _, _ := cert.UnmarshalNebulaCertificateFromPEM(b)
			fmt.Println(nc.Details.PublicKey)
			if reflect.DeepEqual(nc.Details.PublicKey, publicKey) {
				return true
			}
		}
	}

	return false
}

// the readExistingCert function verifies if the given hostname has already an issued certificate. If so, fills the empty fields of its Nebula CSR.
func readExistingCert(csr *models.RawNebulaCsr) error {
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
	*csr.Ip = nc.Details.Ips[0].String()
	if !*csr.Rekey {
		csr.PublicKey = nc.Details.PublicKey
	}

	return nil
}

/*
 * The generateCertificate function creates a new Nebula certificate for the given Nebula CSR.
 * To do so, it either signs the client-provided public key or generates the Nebula key pair and then signs it depending on the option discriminator (ENROLL, SERVERKEYGEN))
 */
func generateCertificate(csr *models.RawNebulaCsr, option int) (*models.CaResponse, error) {
	var (
		ca_response = &models.CaResponse{}
		groups      string
		ip          string
		err         error
	)
	for _, s := range csr.Groups {
		groups += s + ","
	}

	ip = *csr.Ip
	if option == models.SERVERKEYGEN {
		out, err := exec.Command(utils.Ca_bin, "keygen", "-out-pub", utils.Certificates_path+csr.Hostname+".pub", "-out-key", utils.Certificates_path+csr.Hostname+".key").CombinedOutput()
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

	var out []byte
	if len(groups) == 0 {
		if len(utils.Certs_validity) == 0 {
			out, err = exec.Command(utils.Ca_bin, "sign", "-ca-crt", utils.Ca_keys_path+"ca.crt", "-ca-key", utils.Ca_keys_path+"ca.key", "-in-pub", utils.Certificates_path+csr.Hostname+".pub", "-name", csr.Hostname, "-out-crt", utils.Certificates_path+csr.Hostname+".crt", "-ip", ip).CombinedOutput()
		} else {
			out, err = exec.Command(utils.Ca_bin, "sign", "-ca-crt", utils.Ca_keys_path+"ca.crt", "-ca-key", utils.Ca_keys_path+"ca.key", "-in-pub", utils.Certificates_path+csr.Hostname+".pub", "-name", csr.Hostname, "-out-crt", utils.Certificates_path+csr.Hostname+".crt", "-ip", ip, "-duration", utils.Certs_validity).CombinedOutput()
		}
	} else {
		if len(utils.Certs_validity) == 0 {
			out, err = exec.Command(utils.Ca_bin, "sign", "-ca-crt", utils.Ca_keys_path+"ca.crt", "-ca-key", utils.Ca_keys_path+"ca.key", "-in-pub", utils.Certificates_path+csr.Hostname+".pub", "-groups", groups[:len(groups)-1], "-name", csr.Hostname, "-out-crt", utils.Certificates_path+csr.Hostname+".crt", "-ip", ip).CombinedOutput()
		} else {
			out, err = exec.Command(utils.Ca_bin, "sign", "-ca-crt", utils.Ca_keys_path+"ca.crt", "-ca-key", utils.Ca_keys_path+"ca.key", "-in-pub", utils.Certificates_path+csr.Hostname+".pub", "-groups", groups[:len(groups)-1], "-name", csr.Hostname, "-out-crt", utils.Certificates_path+csr.Hostname+".crt", "-ip", ip, "-duration", utils.Certs_validity).CombinedOutput()
		}
	}
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

func getRawCaResponse(ca_response *models.CaResponse) ([]byte, error) {
	raw_bytes, err := ca_response.NebulaCert.Marshal()
	if err != nil {
		fmt.Println("Error in marshalling ca_response.NebulaCert:" + err.Error())
		return nil, &models.ApiError{Code: 500, Message: "Internal Server Error: " + err.Error()}
	}
	raw_cert := &cert.RawNebulaCertificate{}
	if proto.Unmarshal(raw_bytes, raw_cert) != nil {
		fmt.Println("Error in unmarshalling RawNebulaCert:" + err.Error())
		return nil, &models.ApiError{Code: 500, Message: "Internal Server Error: " + err.Error()}
	}
	raw_ca_response := models.RawCaResponse{
		NebulaCert: raw_cert,
	}
	b, err := proto.Marshal(&raw_ca_response)
	if err != nil {
		fmt.Println("Error in marshalling RawCaResponse:" + err.Error())
		return nil, &models.ApiError{Code: 500, Message: "Internal Server Error: " + err.Error()}
	}
	return b, nil
}

/*
 * The CertificateSign REST endpoint creates a new Nebula certificate by signing the client provided Nebula Public Key.
 * It verifies if the provided Proof of Possession is valid for the given Public key before returning the certificate back to the client.
 */
func CertificateSign(c *gin.Context) {
	var raw_csr models.RawNebulaCsr

	if err := c.ShouldBindJSON(&raw_csr); err != nil {
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
	if invalidPublickey := checkPublicKey(raw_csr.PublicKey); invalidPublickey {
		c.JSON(http.StatusBadRequest, models.ApiError{Code: 400, Message: "Bad request: the provided public key is already used by an already enrolled host"})
		return
	}
	if raw_csr.Ip == nil || len(*raw_csr.Ip) == 0 {
		if err := readExistingCert(&raw_csr); err != nil {
			fmt.Println("Internal server Error: " + err.Error())
			c.JSON(http.StatusInternalServerError, err)
			return
		}
	}

	if err := os.WriteFile(utils.Certificates_path+raw_csr.Hostname+".pub", cert.MarshalX25519PublicKey(raw_csr.PublicKey), 0600); err != nil {
		fmt.Println("Internal server Error: " + err.Error())
		c.JSON(http.StatusInternalServerError, models.ApiError{Code: 500, Message: err.Error()})
		return
	}

	ca_response, err := generateCertificate(&raw_csr, models.ENROLL)
	if err != nil {
		fmt.Println("Internal server Error: " + err.Error())
		c.JSON(http.StatusInternalServerError, err)
		return
	}

	b, err := getRawCaResponse(ca_response)
	if err != nil {
		c.JSON(http.StatusInternalServerError, err)
	}

	c.JSON(http.StatusOK, b)
}

// The GenerateKeys REST endpoint creates a new Nebula certificate by generating the Nebula private key and certificate for the given hostname.
func GenerateKeys(c *gin.Context) {
	fmt.Println("Certificate Signing Request arrived")

	var raw_csr models.RawNebulaCsr

	if err := c.ShouldBindJSON(&raw_csr); err != nil {
		c.JSON(http.StatusBadRequest, models.ApiError{Code: 400, Message: "Bad request: no Nebula Certificate Signing Request provided"})
		return
	}

	if raw_csr.Ip == nil || len(*raw_csr.Ip) == 0 {
		if err := readExistingCert(&raw_csr); err != nil {
			fmt.Println("Internal server Error: " + err.Error())
			c.JSON(http.StatusInternalServerError, models.ApiError{Code: 500, Message: err.Error()})
			return
		}
	}

	ca_response, err := generateCertificate(&raw_csr, models.SERVERKEYGEN)
	if err != nil {
		c.JSON(http.StatusInternalServerError, err)
		return
	}
	b, err := getRawCaResponse(ca_response)
	if err != nil {
		c.JSON(http.StatusInternalServerError, err)
	}

	c.JSON(http.StatusOK, b)
}
