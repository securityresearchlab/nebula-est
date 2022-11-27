/*
# Nebula CA service for NEST (Nebula Enrollment over Secure Transport) - OpenAPI 3.0
This is a simple Nebula CA service that signs Nebula Public keys and generates Nebula Key Pairs and Certificates on behalf of the NEST service

API version: 0.3.1
Contact: gianmarco.decola@studio.unibo.it
*/
package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/gin-gonic/gin"
	ca "github.com/m4rkdc/nebula_est/app/nest_ca"
	"github.com/m4rkdc/nebula_est/pkg/utils"
)

/*
nest_ca is a REST API server which acts as a Nebula CA service for the NEST system.
In the main function, the proper environment is set up before starting a Gin http server over a
Nebula network for authentication and confidentiality among the peers (NEST , NEST_CA and NEST_CONFIG services)
*/
func main() {
	if val, ok := os.LookupEnv("CA_NAME"); ok {
		ca.Ca_name = val
	}
	if val, ok := os.LookupEnv("LOG_FILE"); ok {
		ca.Log_file = val
	}

	if val, ok := os.LookupEnv("SERVICE_IP"); ok {
		ca.Service_ip = val
	}
	if val, ok := os.LookupEnv("SERVICE_PORT"); ok {

		ca.Service_port = val
	}
	if val, ok := os.LookupEnv("CERTIFICATES_PATH"); ok {
		ca.Certificates_path = val
	}
	if val, ok := os.LookupEnv("CA_BIN_PATH"); ok {
		ca.Ca_bin = val
	}
	if val, ok := os.LookupEnv("CA_KEYS_PATH"); ok {
		ca.Ca_keys_path = val
	}

	if val, ok := os.LookupEnv("NEBULA_FOLDER"); ok {
		ca.Nebula_folder = val
	}

	fmt.Println("Service started")

	if _, err := os.Stat(ca.Certificates_path); err != nil {
		fmt.Printf("%s doesn't exist. Creating the folder\n", ca.Certificates_path)
		if err := os.Mkdir(ca.Certificates_path, 0700); err != nil {
			fmt.Println("Couldn't create /ncsr directory")
			os.Exit(1)
		}
	}
	info, err := os.Stat(ca.Ca_bin)
	if err != nil {
		fmt.Printf("%s doesn't exist. Cannot proceed. Please provide the nebula-cert bin to the service before starting it\nExiting...", ca.Ca_bin)
		os.Exit(2)
	}
	if !utils.IsExecOwner(info.Mode()) {
		os.Chmod(ca.Ca_bin, 0700)
	}

	info, err = os.Stat(ca.Ca_keys_path + "ca.key")
	if err != nil {
		fmt.Printf("%sca.key doesn't exist. Creating Nebula CA keys...\n", ca.Ca_keys_path)
		cmd := exec.Command(ca.Ca_bin, "ca -name "+ca.Ca_name+" -out-key "+ca.Ca_keys_path+"ca.key"+" -out-crt "+ca.Ca_keys_path+"ca.crt")
		err = cmd.Run()
		if err != nil {
			fmt.Println("Error creating Nebula keys. Exiting...")
			os.Exit(3)
		}
	}
	if !utils.IsRWOwner(info.Mode()) {
		os.Chmod(ca.Ca_keys_path+"ca.key", 0600)
		os.Chmod(ca.Ca_keys_path+"ca.crt", 0600)
	}

	if _, err := os.Stat(ca.Nebula_folder + "nest_ca.crt"); err != nil {
		fmt.Printf("Cannot find NEST CA Nebula certificate\n")
		os.Exit(5)
	}
	if _, err := os.Stat(ca.Nebula_folder + "nest_ca.key"); err != nil {
		fmt.Printf("Cannot find NEST CA Nebula key\n")
		os.Exit(6)
	}
	if _, err := os.Stat(ca.Nebula_folder + "ca.crt"); err != nil {
		fmt.Printf("Cannot find NEST CA ca crt\n")
		os.Exit(7)
	}

	if _, err := os.Stat(ca.Nebula_folder + "config.yml"); err != nil {
		fmt.Printf("Cannot find NEST Nebula config\n")
		os.Exit(8)
	}

	if err = utils.SetupNebula(ca.Nebula_folder); err != nil {
		fmt.Printf("There was an error setting up the Nebula tunnel:%v\n", err.Error())
		os.Exit(9)
	}

	fmt.Println("Service setup finished")

	router := gin.Default()
	utils.SetupLogger(router, ca.Log_file)
	for _, r := range ca.Ca_routes {
		switch r.Method {
		case "GET":
			router.GET(r.Pattern, r.HandlerFunc)
		case "POST":
			router.POST(r.Pattern, r.HandlerFunc)
		}
	}

	router.Run(ca.Service_ip + ":" + ca.Service_port)
}
