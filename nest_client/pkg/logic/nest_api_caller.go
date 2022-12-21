package logic

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/m4rkdc/nebula_est/nest_service/pkg/models"
	"github.com/slackhq/nebula/cert"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

var (
	Nest_service_ip    string
	Nest_service_port  string
	Bin_folder         string
	Nebula_auth        string
	Hostname           string
	Rekey              bool
	Enroll_chan        = make(chan time.Duration)
	Nebula_conf_folder string
	Nest_certificate   string
)

// todo: check nebula-cert generation times
func reenrollAfter(crt cert.NebulaCertificate) {
	os.WriteFile("ncsr_status", []byte("Completed\n"+crt.Details.NotAfter.String()), 0600)
	Enroll_chan <- time.Until(crt.Details.NotAfter)
}

func setupTLSClient() *http.Client {
	caCert, err := os.ReadFile(Nest_certificate)
	if err != nil {
		fmt.Println("Error in reading NEST certificate: " + err.Error())
		return nil
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12,
			MaxVersion:               tls.VersionTLS13,
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			},
			RootCAs: caCertPool},
	}
	client := &http.Client{Transport: tr}
	return client
}

func getCSRResponse(response_bytes []byte) (*models.NebulaCsrResponse, error) {
	raw_csr_response := &models.RawNebulaCsrResponse{}
	csr_response := &models.NebulaCsrResponse{}
	var raw_csr_response_bytes []byte

	if json.Unmarshal(response_bytes, &raw_csr_response_bytes) != nil {
		fmt.Println("There was an error unmarshalling json response")
		return nil, &models.ApiError{Code: 500, Message: "There was an error unmarshalling json response"}
	}
	if proto.Unmarshal(raw_csr_response_bytes, raw_csr_response) != nil {
		fmt.Println("There was an error unmarshalling raw_csr_response_bytes")
		return nil, &models.ApiError{Code: 500, Message: "There was an error unmarshalling raw_csr_response_bytes"}
	}
	csr_response.NebulaConf = raw_csr_response.NebulaConf
	csr_response.NebulaPrivateKey = raw_csr_response.NebulaPrivateKey
	if raw_csr_response.NebulaPath != nil {
		csr_response.NebulaPath = *raw_csr_response.NebulaPath
	}

	raw_cert_bytes, err := proto.Marshal(raw_csr_response.NebulaCert)
	if err != nil {
		fmt.Println("There was an error marshalling raw_csr_response.NebulaCert" + err.Error())
		return nil, &models.ApiError{Code: 500, Message: "There was an error unmarshalling json response"}
	}

	crt, err := cert.UnmarshalNebulaCertificate(raw_cert_bytes)
	if err != nil {
		fmt.Println("There was an error unmarshalling raw_cert_bytes" + err.Error())
		return nil, &models.ApiError{Code: 500, Message: "There was an error unmarshalling raw_cert_bytes"}
	}
	csr_response.NebulaCert = *crt.Copy()
	return csr_response, nil
}

func GetCACerts() error {
	client := setupTLSClient()
	if client == nil {
		return errors.New("error in reading nest certificate")
	}
	resp, err := client.Get("https://" + Nest_service_ip + ":" + Nest_service_port + "/cacerts")
	if err != nil {
		return err
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	//var response []cert.NebulaCertificate
	var response []byte
	var error_response *models.ApiError
	switch {
	case resp.StatusCode == 200:

		err = json.Unmarshal(b, &response)
		if err != nil {
			return err
		}
		os.WriteFile("ca.crt", response, 0600)
		/*
			file, err := os.OpenFile("ca.crt", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			for _, nc := range response {
				b, err := nc.MarshalToPEM()
				if err != nil {
					return err
				}
				file.Write(b)
			}
			file.Close()
		*/

	case resp.StatusCode >= 400:

		if json.Unmarshal(b, error_response) == nil {
			if error_response != nil {
				return error_response
			}
		} else {
			return errors.New("issues unmarshalling json error response: " + string(b))
		}
	}
	return nil
}

func AuthorizeHost() error {
	var auth models.NestAuth

	auth.Hostname = Hostname
	b, err := os.ReadFile(Nebula_auth)
	if err != nil {
		return err
	}

	auth.Secret, err = hex.DecodeString(string(b))
	fmt.Println(string(b))
	fmt.Println(auth.Secret)
	if err != nil {
		return err
	}
	authBytes, _ := json.Marshal(auth)
	client := setupTLSClient()
	if client == nil {
		return errors.New("error in reading nest certificate")
	}
	resp, err := client.Post("https://"+Nest_service_ip+":"+Nest_service_port+"/ncsr", "application/json", bytes.NewReader(authBytes))

	if err != nil {
		return err
	}

	b, err = io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var error_response *models.ApiError

	switch {
	case resp.StatusCode == 201:
		os.WriteFile("ncsr_status", []byte("Pending"), 0600)
	case resp.StatusCode >= 400:
		if json.Unmarshal(b, &error_response) == nil {
			if error_response.Code != 0 {
				return error_response
			} else {
				fmt.Println("There was an error unmarshalling the error response: " + err.Error())
				return err
			}
		} else {
			return errors.New("issues unmarshalling json error response: " + string(b))
		}
	}

	return nil
}

func Enroll() error {

	var csr models.NebulaCsr

	csr.Hostname = Hostname
	out, err := exec.Command(Bin_folder+"nebula-cert", "keygen", "-out-pub", csr.Hostname+".pub", "-out-key", csr.Hostname+".key").CombinedOutput()
	if err != nil {
		fmt.Println("There was an error creating the Nebula key pair: " + string(out))
		return err
	}

	b, err := os.ReadFile(csr.Hostname + ".pub")
	if err != nil {
		return err
	}
	os.Remove(csr.Hostname + ".pub")
	csr.PublicKey, _, err = cert.UnmarshalX25519PublicKey(b)
	if err != nil {
		return err
	}
	raw_csr := models.RawNebulaCsr{
		Hostname:  csr.Hostname,
		PublicKey: csr.PublicKey,
	}

	csr_bytes, err := protojson.Marshal(&raw_csr)
	if err != nil {
		return err
	}
	client := setupTLSClient()
	if client == nil {
		return errors.New("error in reading nest certificate")
	}
	resp, err := client.Post("https://"+Nest_service_ip+":"+Nest_service_port+"/ncsr/"+Hostname+"/enroll", "application/json", bytes.NewReader(csr_bytes))

	if err != nil {
		return err
	}

	b, err = io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var error_response *models.ApiError
	var csr_response *models.NebulaCsrResponse
	switch {
	case resp.StatusCode == 200:
		csr_response, err = getCSRResponse(b)
		if err != nil {
			return err
		}
		Nebula_conf_folder = csr_response.NebulaPath
		os.Mkdir(Nebula_conf_folder, 0700)
		os.Rename(csr.Hostname+".key", Nebula_conf_folder+csr.Hostname+".key")
		os.Rename("ca.crt", Nebula_conf_folder+"ca.crt")
		os.WriteFile(Nebula_conf_folder+"config.yml", csr_response.NebulaConf, 0600)

		b, err = csr_response.NebulaCert.MarshalToPEM()
		if err != nil {
			return err
		}
		os.WriteFile(Nebula_conf_folder+Hostname+".crt", b, 0600)
		reenrollAfter(csr_response.NebulaCert)

	case resp.StatusCode >= 400:
		if json.Unmarshal(b, &error_response) == nil {
			if error_response.Code != 0 {
				return error_response
			} else {
				fmt.Println("There was an error unmarshalling the error response: " + err.Error())
				return err
			}
		} else {
			return errors.New("issues unmarshalling json error response: " + string(b))
		}
	}
	return nil
}

func ServerKeygen() error {
	var csr models.NebulaCsr

	csr.Hostname = Hostname
	csr.ServerKeygen = true
	raw_csr := models.RawNebulaCsr{
		Hostname:     csr.Hostname,
		ServerKeygen: &csr.ServerKeygen,
	}

	csr_bytes, err := protojson.Marshal(&raw_csr)
	if err != nil {
		return err
	}
	client := setupTLSClient()
	if client == nil {
		return errors.New("error in reading nest certificate")
	}
	resp, err := client.Post("https://"+Nest_service_ip+":"+Nest_service_port+"/ncsr/"+Hostname+"/serverkeygen", "application/json", bytes.NewReader(csr_bytes))

	if err != nil {
		return err
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var error_response *models.ApiError
	var csr_response *models.NebulaCsrResponse
	switch {
	case resp.StatusCode == 200:
		csr_response, err = getCSRResponse(b)
		if err != nil {
			return err
		}
		Nebula_conf_folder = csr_response.NebulaPath
		os.Mkdir(Nebula_conf_folder, 0700)
		Nebula_conf_folder = csr_response.NebulaPath
		key := cert.MarshalX25519PrivateKey(b)
		os.WriteFile(Nebula_conf_folder+csr.Hostname+".key", key, 0600)
		os.Rename("ca.crt", Nebula_conf_folder+"ca.crt")
		os.WriteFile(Nebula_conf_folder+"config.yml", csr_response.NebulaConf, 0600)
		b, err = csr_response.NebulaCert.MarshalToPEM()
		if err != nil {
			return err
		}
		os.WriteFile(Nebula_conf_folder+Hostname+".crt", b, 0600)
		reenrollAfter(csr_response.NebulaCert)

	case resp.StatusCode >= 400:
		if json.Unmarshal(b, error_response) != nil {
			if error_response != nil {
				return error_response
			}
		}
	}
	return nil
}

func Reenroll() {
	var csr models.NebulaCsr

	csr.Hostname = Hostname

	if Rekey {
		csr.Rekey = Rekey
		if _, err := os.Stat(Bin_folder + "nebula-cert"); err != nil {
			csr.ServerKeygen = true
		} else {
			os.Remove(Nebula_conf_folder + Hostname + ".key")
			out, err := exec.Command(Bin_folder+"nebula-cert", "keygen", "-out-pub", csr.Hostname+".pub", "-out-key", Nebula_conf_folder+Hostname+".key").CombinedOutput()
			if err != nil {
				fmt.Println("There was an error creating the Nebula key pair: " + string(out))
				Enroll_chan <- -1 * time.Second
				return
			}

			b, err := os.ReadFile(csr.Hostname + ".pub")
			if err != nil {
				Enroll_chan <- -1 * time.Second
				return
			}
			os.Remove(csr.Hostname + ".pub")
			csr.PublicKey, _, err = cert.UnmarshalX25519PublicKey(b)
			if err != nil {
				Enroll_chan <- -1 * time.Second
				return
			}
		}
	}
	raw_csr := models.RawNebulaCsr{
		Hostname:     csr.Hostname,
		PublicKey:    csr.PublicKey,
		Rekey:        &csr.Rekey,
		ServerKeygen: &csr.ServerKeygen,
	}
	csr_bytes, err := protojson.Marshal(&raw_csr)
	if err != nil {
		Enroll_chan <- -1 * time.Second
		return
	}

	client := setupTLSClient()
	if client == nil {
		Enroll_chan <- -1 * time.Second
		return
	}
	resp, err := client.Post("https://"+Nest_service_ip+":"+Nest_service_port+"/ncsr/"+Hostname+"/reenroll", "application/json", bytes.NewReader(csr_bytes))

	if err != nil {
		Enroll_chan <- -1 * time.Second
		return
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		Enroll_chan <- -1 * time.Second
		return
	}
	var error_response *models.ApiError
	var csr_response *models.NebulaCsrResponse
	switch {
	case resp.StatusCode == 200:
		csr_response, err = getCSRResponse(b)
		if err != nil {
			Enroll_chan <- -1 * time.Second
			return
		}
		if csr.ServerKeygen {
			key := cert.MarshalX25519PrivateKey(csr_response.NebulaPrivateKey)
			os.WriteFile(Nebula_conf_folder+csr.Hostname+".key", key, 0600)
		}

		b, err = csr_response.NebulaCert.MarshalToPEM()
		if err != nil {
			Enroll_chan <- -1 * time.Second
			return
		}
		os.Remove(Nebula_conf_folder + Hostname + ".crt")
		os.WriteFile(Nebula_conf_folder+Hostname+".crt", b, 0600)
		reenrollAfter(csr_response.NebulaCert)

	case resp.StatusCode >= 400:
		if json.Unmarshal(b, error_response) != nil {
			if error_response != nil {
				Enroll_chan <- -1 * time.Second
				return
			}
		}
	}
}
