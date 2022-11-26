/*
 * Nebula CA service for NEST (Nebula Enrollment over Secure Transport) - OpenAPI 3.0
 *
 * This is a simple Nebula CA service that signs Nebula Public keys and generates Nebula Key Pairs and Certificates on behalf of the NEST service
 *
 * API version: 0.2.1
 * Contact: gianmarco.decola@studio.unibo.it
 */
package main

import (
	"fmt"
	"os"

	"github.com/gin-gonic/gin"
	conf "github.com/m4rkdc/nebula_est/app/nest_config"
	"github.com/m4rkdc/nebula_est/pkg/utils"
)

/*
 * nest_config is a REST API server which acts as a Nebula Config service for the NEST system.
 * In the main function, the proper environment is set up before starting a Gin http server over a
 * Nebula network for authentication and confidentiality among the peers (NEST , NEST_CA and NEST_CONFIG services)
 */
func main() {
	if val, ok := os.LookupEnv("LOG_FILE"); ok {
		conf.Log_file = val
	}

	if val, ok := os.LookupEnv("SERVICE_IP"); ok {
		conf.Service_ip = val
	}
	if val, ok := os.LookupEnv("SERVICE_PORT"); ok {

		conf.Service_port = val
	}
	if val, ok := os.LookupEnv("DHALL_DIR"); ok {
		conf.Dhall_dir = val
	}
	if val, ok := os.LookupEnv("CONF_GEN_DIR"); ok {
		conf.Conf_gen_dir = val
	}

	if val, ok := os.LookupEnv("NEBULA_FOLDER"); ok {
		conf.Nebula_folder = val
	}

	fmt.Println("Service started")

	info, err := os.Stat(conf.Dhall_dir + "dhall-nebula")
	if err != nil {
		fmt.Printf("%s doesn't exist. Cannot proceed. Please provide the dhall-nebula bin to the service before starting it\nExiting...", conf.Dhall_dir+"dhall-nebula")
		os.Exit(2)
	}
	if !utils.IsExecOwner(info.Mode()) {
		os.Chmod(conf.Dhall_dir+"dhall-nebula", 0700)
	}

	if _, err := os.Stat(conf.Nebula_folder + "nest_config.crt"); err != nil {
		fmt.Printf("Cannot find NEST CA Nebula certificate\n")
		os.Exit(5)
	}
	if _, err := os.Stat(conf.Nebula_folder + "nest_config.key"); err != nil {
		fmt.Printf("Cannot find NEST CA Nebula key\n")
		os.Exit(6)
	}
	if _, err := os.Stat(conf.Nebula_folder + "ca.crt"); err != nil {
		fmt.Printf("Cannot find NEST CA ca crt\n")
		os.Exit(7)
	}

	if _, err := os.Stat(conf.Nebula_folder + "config.yml"); err != nil {
		fmt.Printf("Cannot find NEST Nebula config\n")
		os.Exit(8)
	}

	if err = utils.SetupNebula(conf.Nebula_folder); err != nil {
		fmt.Printf("There was an error setting up the Nebula tunnel:%v\n", err.Error())
		os.Exit(9)
	}

	fmt.Println("Service setup finished")

	router := gin.Default()
	utils.SetupLogger(router, conf.Log_file)
	for _, r := range conf.Conf_routes {
		switch r.Method {
		case "GET":
			router.GET(r.Pattern, r.HandlerFunc)
		case "POST":
			router.POST(r.Pattern, r.HandlerFunc)
		}
	}

	router.Run(conf.Service_ip + ":" + conf.Service_port)
}
