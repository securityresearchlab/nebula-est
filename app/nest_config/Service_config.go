/*
 * Nebula Configuration service for NEST (Nebula Enrollment over Secure Transport) - OpenAPI 3.0
 *
 * This is a simple Nebula Configuration service that generates Nebula configuration files from Dhall configuration files on behalf of the NEST service
 *
 * API version: 0.2.1
 * Contact: gianmarco.decola@studio.unibo.it
 */
package conf

import (
	"github.com/m4rkdc/nebula_est/pkg/models"
)

var (
	Dhall_dir     string = "dhall/"
	Conf_gen_dir  string = Dhall_dir + "nebula/"
	Log_file      string = "log/nest_config.log"
	Service_ip    string = "192.168.80.3"
	Service_port  string = "61616"
	Nebula_folder string = "config/nebula/"
)

var Conf_routes = [2]models.Route{
	{
		Name:        "GenerateConfig",
		Method:      "GET",
		Pattern:     "configs/:hostname",
		HandlerFunc: GenerateConfig,
	},
	{
		Name:        "GetValidHostnames",
		Method:      "GET",
		Pattern:     "/hostnames",
		HandlerFunc: GetValidHostnames,
	},
}
