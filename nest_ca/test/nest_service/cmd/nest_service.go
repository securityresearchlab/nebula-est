/*
# Nebula Enrollment over Secure Transport - OpenAPI 3.0

This is a simple Public Key Infrastructure Management Server based on the RFC7030 Enrollment over Secure Transport Protocol for a Nebula Mesh Network.
The Service accepts requests from TLS connections to create Nebula Certificates for the client (which will be authenticated by providing a secret).
The certificate creation is done either by signing client-generated Nebula Public Keys or by generating Nebula key pairs and signing the server-generated
Nebula public key and to create Nebula configuration files for the specific client. This Service acts as a Facade for the Nebula CA service
(actually signign or creating the Nebula keys) and the Nebula Config service (actually creating the nebula Config. files).

API version: 0.3.1
Contact: gianmarco.decola@studio.unibo.it
*/
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/m4rkdc/nebula_est/nest_service/pkg/logic"
	"github.com/m4rkdc/nebula_est/nest_service/pkg/models"
	"github.com/m4rkdc/nebula_est/nest_service/pkg/utils"
)

// getHostnames sends an http request to the nest_config service over a Nebula network to get the valid hostnames.
func getHostnames() ([]string, error) {
	resp, err := http.Get("http://" + utils.Conf_service_ip + ":" + utils.Conf_service_port + "/hostnames")
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
	var response []string
	err = json.Unmarshal(b, &response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

/*
checkHostnamesFile checks if the file containing all the valid hostnames already exists.
If not, it creates it and populates it by sending a request to the nest_config service
*/
func checkHostnamesFile() error {
	if _, err := os.Stat(utils.Hostnames_file); err != nil {
		log.Printf("%s doesn't exist. Creating it and requesting the cert from Nebula CA service\n", utils.Hostnames_file)
		hostnames, err := getHostnames()
		if err != nil {
			log.Fatalf("There has been an error with the hostnames request: %v", err.Error())
			return err
		}

		file, err := os.OpenFile(utils.Hostnames_file, os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			log.Fatalf("Could not write to file: %v", err)
			return err
		}
		defer file.Close()

		for _, h := range hostnames {
			file.WriteString(h + "\n")
		}
	}
	return nil
}

// SetupTLS sets up the tls configuration for the nest_service server
func setupTLS() *tls.Config {
	var tls_config = tls.Config{
		MinVersion:               tls.VersionTLS12,
		MaxVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}
	return &tls_config
}

/*
nest_service is a REST API server which acts a facade between NEST clients and the inner Nebula CA and configuration services.
In the main function, the proper environment is set up before starting a Gin https server rechable by the clients and an http client over a
Nebula network for authentication and confidentiality among the peers (NEST , NEST_CA and NEST_CONFIG services)
*/
func main() {
	if val, ok := os.LookupEnv("LOG_FILE"); ok {
		utils.Log_file = val
	}

	if val, ok := os.LookupEnv("SERVICE_IP"); ok {
		utils.Service_ip = val
	}
	if val, ok := os.LookupEnv("SERVICE_PORT"); ok {

		utils.Service_port = val
	}
	if val, ok := os.LookupEnv("HOSTNAMES_FILE"); ok {
		utils.Hostnames_file = val
	}
	if val, ok := os.LookupEnv("CA_CERT_FILE"); ok {
		utils.Ca_cert_file = val
	}
	if val, ok := os.LookupEnv("NEBULA_FOLDER"); ok {
		utils.Nebula_folder = val
	}
	if val, ok := os.LookupEnv("HMAC_KEY"); ok {
		utils.HMAC_key = val
	}

	if err := nest_service.CheckCaCertFile(); err != nil {
		fmt.Println("Could not contact the CA service")
		os.Exit(2)
	}
	if err := checkHostnamesFile(); err != nil {
		fmt.Println("Could not contact the Conf service")
		os.Exit(3)
	}

	if _, err := os.Stat("/ncsr"); err != nil {
		if err := os.Mkdir("/ncsr", 0700); err != nil {
			fmt.Printf("Couldn't create /ncsr directory")
			os.Exit(4)
		}
	}

	if _, err := os.Stat(utils.Nebula_folder + "nest_service.crt"); err != nil {
		fmt.Printf("Cannot find NEST service Nebula certificate\n")
		os.Exit(5)
	}
	if _, err := os.Stat(utils.Nebula_folder + "nest_service.key"); err != nil {
		fmt.Printf("Cannot find NEST service Nebula key\n")
		os.Exit(6)
	}

	if _, err := os.Stat(utils.Nebula_folder + "nest_system_ca.crt"); err != nil {
		fmt.Printf("Cannot find NEST Nebula CA crt\n")
		os.Exit(7)
	}

	if _, err := os.Stat(utils.Nebula_folder + "config.yml"); err != nil {
		fmt.Printf("Cannot find NEST Nebula config\n")
		os.Exit(8)
	}

	if err := utils.SetupNebula(utils.Nebula_folder); err != nil {
		fmt.Printf("There was an error setting up the Nebula tunnel:%v\n", err.Error())
		os.Exit(9)
	}

	if _, err := os.Stat(utils.TLS_folder + "nest_key.pem"); err != nil {
		fmt.Printf("Cannot find NEST service TLS key\n")
		os.Exit(10)
	}

	if _, err := os.Stat(utils.Nebula_folder + "nest_crt.pem"); err != nil {
		fmt.Printf("Cannot find NEST TLS crt\n")
		os.Exit(11)
	}

	info, err := os.Stat(utils.HMAC_key)
	if err != nil {
		fmt.Printf("Cannot find HMAC key\n")
		os.Exit(12)
	}

	if !utils.IsRWOwner(info.Mode()) {
		os.Chmod(utils.HMAC_key, 0600)
	}

	tls_config := setupTLS()

	router := gin.Default()
	utils.SetupLogger(router, utils.Log_file)

	for _, r := range nest_service.Service_routes {
		switch r.Method {
		case "GET":
			router.GET(r.Pattern, r.HandlerFunc)
		case "POST":
			router.POST(r.Pattern, r.HandlerFunc)
		}
	}

	srv := http.Server{
		Addr:      utils.Service_ip + ":" + utils.Service_port,
		Handler:   router,
		TLSConfig: tls_config,
	}

	srv.ListenAndServeTLS(utils.TLS_folder+"nest_service-crt.pem", utils.TLS_folder+"nest_service-key.pem")
}