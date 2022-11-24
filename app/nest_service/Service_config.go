/*
 * NEST: Nebula Enrollment over Secure Transport - OpenAPI 3.0
 *
 * This module contains the NEST service routes
 * API version: 0.1.1
 * Contact: gianmarco.decola@studio.unibo.it
 */
package nest_service

import (
	"github.com/m4rkdc/nebula_est/pkg/models"
)

var (
	Hostnames_file    string = "config/hostnames"
	Log_file          string = "log/nest_service.log"
	Ca_cert_file      string = "config/ca.crt"
	Service_ip        string = "localhost"
	Service_port      string = "8080"
	Ca_service_ip     string = "localhost"
	Ca_service_port   string = "5353"
	Conf_service_ip   string = "localhost"
	Conf_service_port string = "61616"
)

const (
	ENROLL = iota
	SERVERKEYGEN
	RENROLL
)

var Service_routes = [6]models.Route{

	{
		Name:        "Cacerts",
		Method:      "GET",
		Pattern:     "/cacerts",
		HandlerFunc: Cacerts,
	},
	{
		Name:        "Enroll",
		Method:      "POST",
		Pattern:     "/ncsr/:hostname/enroll",
		HandlerFunc: Enroll,
	},
	{
		Name:        "NcsrApplication",
		Method:      "POST",
		Pattern:     "/ncsr",
		HandlerFunc: NcsrApplication,
	},
	{
		Name:        "NcsrStatus",
		Method:      "GET",
		Pattern:     "/ncsr/:hostname",
		HandlerFunc: NcsrStatus,
	},
	{
		Name:        "Reenroll",
		Method:      "POST",
		Pattern:     "/ncsr/:hostname/reenroll",
		HandlerFunc: Reenroll,
	},
	{
		Name:        "Serverkeygen",
		Method:      "POST",
		Pattern:     "/ncsr/:hostname/serverkeygen",
		HandlerFunc: Serverkeygen,
	},
}
