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
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/gin-gonic/gin"
	conf "github.com/m4rkdc/nebula_est/app/nest_config"
)

func isExecOwner(mode os.FileMode) bool {
	return mode&0100 != 0
}

func setupLogger(router *gin.Engine) error {
	logF, err := os.OpenFile(conf.Log_file, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	gin.ForceConsoleColor()
	router.Use(gin.LoggerWithConfig(gin.LoggerConfig{
		Output: io.MultiWriter(logF, os.Stdout),
	}))
	return nil
}

func setupNebula() error {
	info, err := os.Stat(conf.Nebula_folder + "nebula")
	if err != nil {
		fmt.Printf("%s doesn't exist. Cannot proceed. Please provide the nebula bin to the service before starting it\nExiting...", conf.Nebula_folder+"nebula")
		return err
	}
	if !isExecOwner(info.Mode()) {
		os.Chmod(conf.Nebula_folder+"nebula", 0700)
	}

	cmd := exec.Command(conf.Nebula_folder+"nebula", "-config "+conf.Nebula_folder+"config.yml")
	if err = cmd.Run(); err != nil {
		return err
	}
	interfaces, err := net.Interfaces()

	if err != nil {
		fmt.Printf("Could'nt check information about host interfaces\n")
		return err
	}

	var found bool = false
	for _, i := range interfaces {
		if strings.Contains(strings.ToLower(i.Name), "nebula") {
			found = true
			break
		}
	}

	if found {
		return nil
	}
	return errors.New("could not setup a nebula tunnel")
}

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
	if !isExecOwner(info.Mode()) {
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

	if err = setupNebula(); err != nil {
		fmt.Printf("There was an error setting up the Nebula tunnel:%v\n", err.Error())
		os.Exit(9)
	}

	fmt.Println("Service setup finished")

	router := gin.Default()
	setupLogger(router)
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
