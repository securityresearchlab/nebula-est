package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	nest_client "github.com/m4rkdc/nebula_est/nest_client/pkg/logic"
)

func setupNebula() error {
	_, err := os.Stat(nest_client.Bin_folder + "nebula")
	if err != nil {
		fmt.Printf("%s doesn't exist. Cannot proceed. Please provide the nebula bin to the service before starting it\nExiting...", nest_client.Bin_folder+"nebula")
		return err
	}
	os.Chmod(nest_client.Bin_folder+"nebula", 0700)

	exec.Command(nest_client.Bin_folder+"nebula", "-config", nest_client.Nebula_conf_folder+"config.yml").Start()

	time.Sleep(2 * time.Second)
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

	if val, ok := os.LookupEnv("NEST_SERVICE_IP"); ok {
		nest_client.Nest_service_ip = val
	}
	if val, ok := os.LookupEnv("NEST_SERVICE_PORT"); ok {

		nest_client.Nest_service_port = val
	}
	if val, ok := os.LookupEnv("NEST_CERT"); ok {
		nest_client.Nest_certificate = val
	}
	if val, ok := os.LookupEnv("BIN_FOLDER"); ok {

		nest_client.Bin_folder = val
	}
	if val, ok := os.LookupEnv("NEBULA_AUTH"); ok {
		nest_client.Nebula_auth = val
	}
	if val, ok := os.LookupEnv("HOSTNAME"); ok {
		nest_client.Hostname = val
	}
	if val, ok := os.LookupEnv("REKEY"); ok {
		nest_client.Rekey, _ = strconv.ParseBool(val)
	}
	fmt.Println("NEST client: starting setup")

	if _, err := os.Stat(nest_client.Nest_certificate); err != nil {
		fmt.Printf("Cannot find NEST service certificate. Please provide the NEST certificate or CA certificate before starting nest_client\n")
		os.Exit(1)
	}
	if _, err := os.Stat(nest_client.Bin_folder + "nebula"); err != nil {
		fmt.Printf("Cannot find nebula binary. Please provide the nebula binary before starting nest_client\n")
		os.Exit(2)
	}

	if _, err := os.Stat(nest_client.Nebula_auth); err != nil {
		fmt.Printf("Cannot find nest_client authorization token. Please provide the authorization token before starting nest_client\n")
		os.Exit(3)
	}

	if len(nest_client.Hostname) == 0 {
		hostname, err := os.Hostname()
		if err != nil {
			fmt.Printf("Cannot load client's hostname from environment. Please provide the hostname or set it in the os before starting nest_client\n")
			os.Exit(4)
		}
		nest_client.Hostname = hostname
	}

	if _, err := os.Stat("ca.crt"); err != nil {
		if err := nest_client.GetCACerts(); err != nil {
			fmt.Printf("There was an error getting the NEST client Nebula Network CAs: %v\n", err.Error())
			os.Exit(5)
		}
	}

	if _, err := os.Stat("ncsr_status"); err != nil {
		if err := nest_client.AuthorizeHost(); err != nil {
			fmt.Printf("There was an error authorizing the nest client: %v\n", err.Error())
			os.Exit(6)
		}
	}

	//todo add error channel
	if _, err := os.Stat(nest_client.Bin_folder + "nebula-cert"); err != nil {
		go nest_client.ServerKeygen()
	} else {
		go nest_client.Enroll()
	}
	if err := setupNebula(); err != nil {
		fmt.Printf("There was an error setting up the Nebula tunnel:%v\n", err)
		os.Exit(7)
	}
	for {
		select {
		case duration := <-nest_client.Enroll_chan:
			if duration.Hours() < 0 {
				fmt.Println("There was an error in the enrollment process")
				os.Exit(9)
			}
			time.AfterFunc(duration, nest_client.Reenroll)

		default:
			continue
		}
	}

}
