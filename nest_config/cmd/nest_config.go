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

	"github.com/gin-gonic/gin"
	nest_config "github.com/m4rkdc/nebula_est/nest_config/pkg/logic"
	"github.com/m4rkdc/nebula_est/nest_service/pkg/utils"
)

/*
nest_config is a REST API server which acts as a Nebula Config service for the NEST system.
In the main function, the proper environment is set up before starting a Gin http server over a
Nebula network for authentication and confidentiality among the peers (NEST , NEST_CA and NEST_CONFIG services)
*/
func main() {
	if val, ok := os.LookupEnv("LOG_FILE"); ok {
		utils.Log_file = val
	}

	if val, ok := os.LookupEnv("SERVICE_IP"); ok {
		utils.Conf_service_ip = val
	}
	if val, ok := os.LookupEnv("SERVICE_PORT"); ok {

		utils.Conf_service_port = val
	}
	if val, ok := os.LookupEnv("DHALL_DIR"); ok {
		utils.Dhall_dir = val
	}
	if val, ok := os.LookupEnv("DHALL_CONFIGURATION"); ok {
		utils.Dhall_configuration = val
	}
	if val, ok := os.LookupEnv("CONF_GEN_DIR"); ok {
		utils.Conf_gen_dir = val
	}

	if val, ok := os.LookupEnv("NEBULA_FOLDER"); ok {
		utils.Nebula_folder = val
	}

	fmt.Println("NEST config service: starting setup")

	info, err := os.Stat(utils.Dhall_dir + "bin/dhall-nebula")
	if err != nil {
		fmt.Printf("%s doesn't exist. Cannot proceed. Please provide the dhall-nebula bin to the service before starting it\nExiting...", utils.Dhall_dir+"dhall-nebula")
		os.Exit(1)
	}
	if !utils.IsExecOwner(info.Mode()) {
		os.Chmod(utils.Dhall_dir+"bin/dhall-nebula", 0700)
	}
	info, err = os.Stat(utils.Dhall_dir + utils.Dhall_configuration)
	if err != nil {
		fmt.Printf("%s doesn't exist. Cannot proceed. Please provide the dhall-nebula network configuration to the service before starting it\nExiting...", utils.Dhall_dir+utils.Dhall_configuration)
		os.Exit(2)
	}
	if !utils.IsRWOwner(info.Mode()) {
		os.Chmod(utils.Dhall_dir+utils.Dhall_configuration, 0600)
	}
	utils.Dhall_last_modified = info.ModTime()

	if _, err := os.Stat(utils.Nebula_folder + "nest_config.crt"); err != nil {
		fmt.Printf("Cannot find NEST config Nebula certificate\n")
		os.Exit(5)
	}
	if _, err := os.Stat(utils.Nebula_folder + "nest_config.key"); err != nil {
		fmt.Printf("Cannot find NEST config Nebula key\n")
		os.Exit(6)
	}
	if _, err := os.Stat(utils.Nebula_folder + "nest_system_ca.crt"); err != nil {
		fmt.Printf("Cannot find NEST config ca crt\n")
		os.Exit(7)
	}

	if _, err := os.Stat(utils.Nebula_folder + "config.yml"); err != nil {
		fmt.Printf("Cannot find NEST Nebula config\n")
		os.Exit(8)
	}

	nebula_log, err := os.OpenFile(utils.Nebula_folder+"nest_config_nebula.log", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Printf("There was an error creating nebula log file: %v\n", err)
		os.Exit(8)
	}
	defer nebula_log.Close()
	if err := utils.SetupNebula(utils.Nebula_folder, nebula_log); err != nil {
		fmt.Printf("There was an error setting up the Nebula tunnel:%v\n", err)
		os.Exit(9)
	}
	if dir, _ := os.ReadDir(utils.Dhall_dir + utils.Conf_gen_dir); len(dir) == 0 {
		if err = nest_config.GenerateAllNebulaConfigs(); err != nil {
			fmt.Println("Could not generate Nebula configuration files: " + err.Error())
			os.Exit(3)
		}
	}

	fmt.Println("NEST config service: setup finished")

	router := gin.Default()
	router.SetTrustedProxies(nil)
	utils.SetupLogger(router, utils.Log_file)
	for _, r := range nest_config.Conf_routes {
		switch r.Method {
		case "GET":
			router.GET(r.Pattern, r.HandlerFunc)
		case "POST":
			router.POST(r.Pattern, r.HandlerFunc)
		}
	}

	router.Run(utils.Conf_service_ip + ":" + utils.Conf_service_port)
}
