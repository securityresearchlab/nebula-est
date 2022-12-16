package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	nest_client "github.com/m4rkdc/nebula_est/nest_client/pkg/logic"
)

func main() {

	if val, ok := os.LookupEnv("NEST_SERVICE_IP"); ok {
		nest_client.Nest_service_ip = val
	}
	if val, ok := os.LookupEnv("NEST_SERVICE_PORT"); ok {

		nest_client.Nest_service_port = val
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

	if _, err := os.Stat(nest_client.Bin_folder + "nebula"); err != nil {
		fmt.Printf("Cannot find nebula binary. Please provide the nebula binary before starting nest_client\n")
		os.Exit(1)
	}

	if _, err := os.Stat(nest_client.Nebula_auth); err != nil {
		fmt.Printf("Cannot find nest_client authorization token. Please provide the authorization token before starting nest_client\n")
		os.Exit(2)
	}

	if len(nest_client.Hostname) == 0 {
		hostname, err := os.Hostname()
		if err != nil {
			fmt.Printf("Cannot load client's hostname from environment. Please provide the hostname or set it in the os before starting nest_client\n")
			os.Exit(3)
		}
		nest_client.Hostname = hostname
	}

	if _, err := os.Stat("ca.crt"); err != nil {
		if err := nest_client.Get_CA_certs(); err != nil {
			fmt.Printf("There was an error getting the NEST client Nebula Network CAs: %v\n", err.Error())
			os.Exit(4)
		}
	}

	if _, err := os.Stat("ncsr_status"); err != nil {
		if err := nest_client.Authorize_host(); err != nil {
			fmt.Printf("There was an error authorizing the nest client: %v\n", err.Error())
			os.Exit(5)
		}
	}

	if _, err := os.Stat(nest_client.Bin_folder + "nebula-cert"); err != nil {
		if err := nest_client.ServerKeygen(); err != nil {
			fmt.Printf("There was an error enrolling with serverkeygen : %v\n", err.Error())
			os.Exit(6)
		}
	} else {
		if err := nest_client.Enroll(); err != nil {
			fmt.Printf("There was an error enrolling: %v\n", err.Error())
			os.Exit(6)
		}
	}
	for {
		select {
		case duration := <-nest_client.Enroll_chan:
			if duration.Hours() < 0 {
				fmt.Println("There was an error reenrolling")
				os.Exit(9)
			}
			time.AfterFunc(duration, nest_client.Reenroll)
		default:
			continue
		}
	}

}
