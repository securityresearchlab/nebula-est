package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	nest_client "github.com/m4rkdc/nebula_est/nest_client/pkg/logic"
)

func uninstall_nebula() {
	fmt.Println("Terminating nebula service...")
	exec.Command(nest_client.Bin_folder+"nebula"+nest_client.File_extension, "-service", "stop").Run()
	fmt.Println("Uninstalling nebula service...")
	exec.Command(nest_client.Bin_folder+"nebula"+nest_client.File_extension, "-service", "uninstall").Run()
}

func setupNebula(nebula_log *os.File) (*exec.Cmd, error) {
	_, err := os.Stat(nest_client.Bin_folder + "nebula" + nest_client.File_extension)
	if err != nil {
		fmt.Printf("%s doesn't exist. Cannot proceed. Please provide the nebula bin to the service before starting it\nExiting...", nest_client.Bin_folder+"nebula"+nest_client.File_extension)
		return nil, err
	}
	os.Chmod(nest_client.Bin_folder+"nebula"+nest_client.File_extension, 0700)
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command(nest_client.Bin_folder+"nebula"+nest_client.File_extension, "-service", "install", "-config", nest_client.Nebula_conf_folder+"config.yml")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stdout
		cmd.Start()
	} else {
		cmd = exec.Command(nest_client.Bin_folder+"nebula"+nest_client.File_extension, "-config", nest_client.Nebula_conf_folder+"config.yml")
		cmd.Stdout = nebula_log
		cmd.Stderr = nebula_log
	}

	if runtime.GOOS == "windows" {
		cmd = exec.Command(nest_client.Bin_folder+"nebula"+nest_client.File_extension, "-service", "start")
		cmd.Stdout = nebula_log
		cmd.Stderr = nebula_log
	}
	cmd.Start()
	time.Sleep(3 * time.Second)

	interfaces, err := net.Interfaces()

	if err != nil {
		fmt.Printf("Could'nt check information about host interfaces\n")
		return nil, err
	}

	var found bool = false
	for _, i := range interfaces {
		if strings.Contains(strings.ToLower(i.Name), "nebula") {
			found = true
			break
		}
	}

	if found {
		return cmd, nil
	}
	return nil, errors.New("could not setup a nebula tunnel")
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
		nest_client.Conf_folder = strings.TrimSuffix(val, "secret.hmac")
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
	if runtime.GOOS == "windows" {
		nest_client.File_extension = ".exe"
	}
	if _, err := os.Stat(nest_client.Bin_folder + "nebula" + nest_client.File_extension); err != nil {
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

	if err := nest_client.GetCACerts(); err != nil {
		fmt.Printf("There was an error getting the NEST client Nebula Network CAs: %v\n", err.Error())
		os.Exit(5)
	}

	if err := nest_client.AuthorizeHost(); err != nil {
		fmt.Printf("There was an error authorizing the nest client: %v\n", err.Error())
		os.Exit(6)
	}
	fmt.Println("NEST client: setup finished")
	//todo add error channel
	if _, err := os.Stat(nest_client.Bin_folder + "nebula-cert" + nest_client.File_extension); err != nil {
		nest_client.ServerKeygen()
	} else {
		nest_client.Enroll()
	}
	fmt.Println("NEST client: enrollment successfull. Writing conf files and keys to " + nest_client.Nebula_conf_folder)
	nebula_log, err := os.OpenFile(nest_client.Nebula_conf_folder+nest_client.Hostname+"_nebula.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Printf("There was an error creating nebula log file: %v\n", err)
		os.Exit(8)
	}
	defer nebula_log.Close()
	cmd, err := setupNebula(nebula_log)
	if err != nil {
		fmt.Printf("There was an error setting up the Nebula tunnel: %v\n", err)
		uninstall_nebula()
		os.Exit(7)
	}

	if runtime.GOOS == "windows" {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		go func() {
			for sig := range c {
				fmt.Println("Caught signal: " + sig.String())
				uninstall_nebula()
			}
		}()

	}

	for {
		select {
		case duration := <-nest_client.Enroll_chan:
			if duration.Hours() < 0 {
				fmt.Println("There was an error in the enrollment process")
				uninstall_nebula()
				os.Exit(9)
			}
			fmt.Println("NEST client: Scheduling re-enrollment in: " + duration.String())
			time.AfterFunc(duration, nest_client.Reenroll)
			time.Sleep(duration + 1*time.Second)
			fmt.Println("Restarting nebula after certificate renewal")
			if runtime.GOOS == "windows" {
				cmd := exec.Command(nest_client.Bin_folder+"nebula"+nest_client.File_extension, "-service", "restart")
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stdout
				cmd.Start()
			} else {
				cmd.Process.Signal(syscall.SIGHUP)
			}
			/*if runtime.GOOS == "windows" {
				cmd.Process = nil
				for {
					if _, err := net.InterfaceByName("nebula"); err != nil {
						if err = cmd.Start(); err != nil {
							fmt.Println("Could not restart nebula: " + err.Error())
						}
						break
					}
				}
			}*/
		default:
			continue
		}
	}

}
