package logic

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/m4rkdc/nebula_est/nest_service/pkg/models"
	"github.com/slackhq/nebula/cert"
)

var (
	Nest_service_ip   string
	Nest_service_port string
	Nebula_folder     string
	Nebula_auth       string
	Hostname          string
	Rekey             bool
	Enroll_chan       = make(chan time.Duration)
)

func getReenrollDuration() {
	b, err := os.ReadFile(Nebula_folder + Hostname + ".crt")
	if err != nil {
		fmt.Printf("There was an error opening the client cert file : %v\n", err.Error())
		os.Exit(7)
	}

	nc, _, err := cert.UnmarshalNebulaCertificateFromPEM(b)
	if err != nil {
		fmt.Printf("There was an error umnarshalling the client cert file : %v\n", err.Error())
		os.Exit(8)
	}
	os.WriteFile("ncsr_status", []byte("Completed\n"+nc.Details.NotAfter.String()), 0600)
	Enroll_chan <- time.Until(nc.Details.NotAfter)
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

	var error_response *models.ApiError
	if json.Unmarshal(b, error_response) != nil {
		if error_response != nil {
			return error_response
		}
	}
	var response []cert.NebulaCertificate
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
	switch resp.StatusCode {
	case 201:
		os.WriteFile("ncsr_status", []byte("Pending"), 0600)
	case 400:
	}

	return nil
}

func ServerKeygen() error {

	getReenrollDuration()
	return nil
}

func Enroll() error {
	os.WriteFile("ncsr_status", []byte("Completed"), 0600)
	getReenrollDuration()
	return nil
}

func Reenroll() {
	os.WriteFile("ncsr_status", []byte("Completed"), 0600)
	getReenrollDuration()
}
