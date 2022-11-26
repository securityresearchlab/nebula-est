package utils

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/gin-gonic/gin"
)

// setupLogger sets up an io.Multiwriter that writes both on LOG_FILE and os.Stout for the given Gin router
func SetupLogger(router *gin.Engine, log_file string) error {
	logF, err := os.OpenFile(log_file, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	gin.ForceConsoleColor()
	router.Use(gin.LoggerWithConfig(gin.LoggerConfig{
		Output: io.MultiWriter(logF, os.Stdout),
	}))
	return nil
}

// isExecOwner checks if an open file can be executed by its owner
func IsExecOwner(mode os.FileMode) bool {
	return mode&0100 != 0
}

// isRWOwner checks if an open file can be read and written by its owner
func IsRWOwner(mode os.FileMode) bool {
	return mode&0600 != 0
}

/*
 * setupNebula controls if the nebula binary is present in NEBULA_FOLDER and, if it is executable, executes it
 * to create a Nebula interface. If the interface is actually created, returns nil, err otherwise
 */
func SetupNebula(nebula_folder string) error {
	info, err := os.Stat(nebula_folder + "nebula")
	if err != nil {
		fmt.Printf("%s doesn't exist. Cannot proceed. Please provide the nebula bin to the service before starting it\nExiting...", nest.Nebula_folder+"nebula")
		return err
	}
	if !IsExecOwner(info.Mode()) {
		os.Chmod(nebula_folder+"nebula", 0700)
	}

	cmd := exec.Command(nebula_folder+"nebula", "-config "+nebula_folder+"config.yml")
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
