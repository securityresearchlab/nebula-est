package logic

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/m4rkdc/nebula_est/nest_service/pkg/models"
	"github.com/slackhq/nebula/cert"
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
)

func reenrollAfter(crt cert.NebulaCertificate) {
	os.WriteFile("ncsr_status", []byte("Completed\n"+crt.Details.NotAfter.String()), 0600)
	Enroll_chan <- time.Until(crt.Details.NotAfter)
}

func Get_CA_certs() error {
	resp, err := http.Get("https://" + Nest_service_ip + ":" + Nest_service_port + "/cacerts")
	if err != nil {
		return err
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var response []cert.NebulaCertificate
	var error_response *models.ApiError
	switch {
	case resp.StatusCode == 200:

		err = json.Unmarshal(b, &response)
		if err != nil {
			return err
		}
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

	case resp.StatusCode >= 400:

		if json.Unmarshal(b, error_response) != nil {
			if error_response != nil {
				return error_response
			}
		}
	}
	return nil
}

func Authorize_host() error {
	var auth models.NestAuth

	auth.Hostname = Hostname
	b, err := os.ReadFile(Nebula_auth)
	if err != nil {
		return err
	}
	auth.Secret = b
	authBytes, _ := json.Marshal(auth)
	resp, err := http.Post("https://"+Nest_service_ip+":"+Nest_service_port+"/ncsr", "application/json", bytes.NewReader(authBytes))

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
		if json.Unmarshal(b, error_response) != nil {
			if error_response != nil {
				return error_response
			}
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
	csrBytes, _ := json.Marshal(csr)
	resp, err := http.Post("https://"+Nest_service_ip+":"+Nest_service_port+"/ncsr/"+Hostname+"/enroll", "application/json", bytes.NewReader(csrBytes))

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
		if json.Unmarshal(b, csr_response) != nil {
			if csr_response != nil {
				fmt.Println("There was an error unmarshalling json response")
				return &models.ApiError{Code: 500, Message: "There was an error unmarshalling json response"}
			}
		}
		Nebula_conf_folder = csr_response.NebulaPath
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
		if json.Unmarshal(b, error_response) != nil {
			if error_response != nil {
				return error_response
			}
		}
	}
	return nil
}

func ServerKeygen() error {
	var csr models.NebulaCsr

	csr.Hostname = Hostname
	csr.ServerKeygen = true
	csrBytes, _ := json.Marshal(csr)
	resp, err := http.Post("https://"+Nest_service_ip+":"+Nest_service_port+"/ncsr/"+Hostname+"/serverkeygen", "application/json", bytes.NewReader(csrBytes))

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
		if json.Unmarshal(b, csr_response) != nil {
			if csr_response != nil {
				fmt.Println("There was an error unmarshalling json response")
				return &models.ApiError{Code: 500, Message: "There was an error unmarshalling json response"}
			}
		}
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
		csrBytes, _ := json.Marshal(csr)
		resp, err := http.Post("https://"+Nest_service_ip+":"+Nest_service_port+"/ncsr/"+Hostname+"/reenroll", "application/json", bytes.NewReader(csrBytes))

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
			if json.Unmarshal(b, csr_response) != nil {
				if csr_response != nil {
					fmt.Println("There was an error unmarshalling json response")
					Enroll_chan <- -1 * time.Second
					return
				}
			}
			if csr.ServerKeygen {
				key := cert.MarshalX25519PrivateKey(b)
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
}
