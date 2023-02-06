/*
 * Nebula Configuration service for NEST (Nebula Enrollment over Secure Transport) - OpenAPI 3.0
 *
 * This is a simple Nebula Configuration service that generates Nebula configuration files from Dhall configuration files on behalf of the NEST service
 *
 * API version: 0.2.1
 * Contact: gianmarco.decola@studio.unibo.it
 */
package models

// Response returned by the Nebula config service to the NEST service
type ConfResponse struct {
	//The newly generated Nebula configuration file.
	NebulaConf []byte `json:"nebulaConf"`
	//Nebula security groups the client will be part of.
	Groups []string `json:"groups,omitempty"`
	//Nebula Ip of the client.
	Ip string `json:"ip"`
	//The client-local path in which the configuration file and nebula certificate has to be installed
	NebulaPath string `json:"NebulaPath"`
}
