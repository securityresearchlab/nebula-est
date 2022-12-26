package nest_config

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/m4rkdc/nebula_est/nest_service/pkg/models"
	"github.com/m4rkdc/nebula_est/nest_service/pkg/utils"
)

var Conf_routes = [3]models.Route{
	{
		Name:        "GetValidHostnames",
		Method:      "GET",
		Pattern:     "/hostnames",
		HandlerFunc: GetValidHostnames,
	},
	{
		Name:        "GetConfig",
		Method:      "GET",
		Pattern:     "/configs/:hostname",
		HandlerFunc: GetConfig,
	},
	/*
		{
			Name:        "ValidateCertificate",
			Method:      "POST",
			Pattern:     "/validate",
			HandlerFunc: ValidateCertificate,
		},*/
}

func parseDhallFiles(b []byte, hostname string) ([]string, string, string, error) {
	var (
		ip      string
		ip_mask []rune
		group   []rune
		groups  []string
		path    string
	)

	start := "key: \""
	end := ".key\""
	low := bytes.Index(b, []byte(start))
	high := bytes.Index(b, []byte(end))
	if low == -1 && high == -1 {
		start = "key: "
		end = ".key"
	}
	low = bytes.Index(b, []byte(start))
	high = bytes.Index(b, []byte(end))
	path = string(b[low+len(start) : high-len(hostname)])

	b, err := os.ReadFile(utils.Dhall_dir + "nebula/hosts/" + hostname + ".dhall")
	if err != nil {
		return nil, "", "", &models.ApiError{Code: 500, Message: "Internal Server Error: " + err.Error()}
	}
	start = "mkIPv4 "
	end = "\n"
	low = bytes.Index(b, []byte(start))
	high = bytes.Index(b[low:], []byte(end)) + low

	ip = strings.ReplaceAll(string(b[low+len(start):high]), " ", ".")

	file, _ := os.Open(utils.Dhall_dir + utils.Dhall_configuration)
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	start = "group_name = \""
	end = "\","
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "ip_mask") {
			low = strings.Index(line, "ip_mask = ")
			for n, v := range line {
				if n < low+len("ip_mask = ") {
					continue
				}
				if v == '\n' {
					break
				}
				ip_mask = append(ip_mask, v)
			}
			if len(ip_mask) != 0 {
				fmt.Println("Ip: " + ip + " Ip mask:" + string(ip_mask))
				ip += "/" + string(ip_mask)
			}
		}
		if strings.Contains(line, "group_name") {
			if strings.Contains(line, hostname) || strings.Contains(line, "hosts_list") {
				low = strings.Index(line, start)
				high = strings.Index(line[low:], end) + low

				for n, v := range line {
					if n < low+len(start) {
						continue
					}
					if n == high {
						break
					}
					group = append(group, v)
				}
				if len(group) != 0 {
					groups = append(groups, string(group))
					group = []rune{}
				}
			}
		}
	}
	return groups, ip, path, nil
}

/*
The GetConfig REST endpoint reads the already generated Nebula config file for the given hostname and returns it.
The ConfResponse also contains the path in which all the keys and configs have to be installed on the client and the IP and Security groups of the client
*/
func GetConfig(c *gin.Context) {
	var conf_resp models.ConfResponse

	hostname := c.Param("hostname")
	if len(strings.TrimSpace(hostname)) == 0 {
		c.JSON(http.StatusBadRequest, models.ApiError{Code: 400, Message: "Bad request: no hostname provided"})
		return
	}

	//Read the whole generated yaml file and return it in conf_resp
	b, err := os.ReadFile(utils.Dhall_dir + "nebula/generated/" + hostname + ".yaml")
	if err != nil {
		fmt.Println("Internal server Error: " + err.Error())
		c.JSON(http.StatusInternalServerError, models.ApiError{Code: 500, Message: "Internal Server Error: " + err.Error()})
		return
	}
	if bytes.Contains(b, []byte("\\")) {
		b = bytes.ReplaceAll(b, []byte("/"), []byte("\\\\"))
		conf_resp.NebulaConf = b
	}
	if len(conf_resp.NebulaConf) == 0 {
		conf_resp.NebulaConf = b
	}

	if conf_resp.Groups, conf_resp.Ip, conf_resp.NebulaPath, err = parseDhallFiles(b, hostname); err != nil {
		c.JSON(http.StatusInternalServerError, err)
	}
	c.JSON(http.StatusOK, conf_resp)
}

/*
func ValidateCertificate(c *gin.Context) {

}
*/
