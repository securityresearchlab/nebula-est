/*
 * Nebula Enrollment over Secure Transport - OpenAPI 3.0
 *
 * This is a simple Public Key Infrastructure Management Server based on the RFC7030 Enrollment over Secure Transport Protocol for a Nebula Mesh Network. The Service accepts requests from mutually authenticated TLS-PSK connections to create Nebula Certificates for the client, either by signing client-generated Nebula Public Keys or by generating Nebula key pairs and signing the server-generated Nebula public key and to create Nebula configuration files for the specific client. This Service acts as a Facade for the Nebula CA service (actually signign or creating the Nebula keys) and the Nebula Config service (actually creating the nebula Config. files).
 *
 * API version: 0.1.1
 * Contact: gianmarco.decola@studio.unibo.it
 */
package models

import (
	"github.com/slackhq/nebula/cert"
)

type NebulaCsrStatus string

// List of NebulaCSRStatus

const (
	ENROLL = iota
	SERVERKEYGEN
	RENROLL
)

const (
	PENDING   NebulaCsrStatus = "Pending"
	COMPLETED NebulaCsrStatus = "Completed"
	EXPIRED   NebulaCsrStatus = "Expired"
)

/*
*	A Nebula Certificate Signing Request. Contains:
  - serverKeygen: indicates if the Nebula key pair has to be generated on the server or not. False if empty
  - rekey: used in re-enrollment CSRs. Indicates if the Nebula key pair has to be regenerated for the new Nebula certificate. False if empty
  - hostname: the hostname of the requesting client. Required
  - publicKey: byte stream indicating the client-generated publicKey. Can be omitted if serverKeygen is true
*/
type NebulaCsr struct {
	//Indicates if the Nebula key pair has to be generated on the server or not. False if empty
	ServerKeygen bool `json:"serverKeygen,omitempty"`
	//Used in re-enrollment CSRs. Indicates if the Nebula key pair has to be regenerated for the new Nebula certificate. False if empty
	Rekey bool `json:"rekey,omitempty"`
	//The hostname of the requesting client. Required
	Hostname string `json:"hostname"`
	//Byte stream indicating the client-generated Nebula public Key. Can be omitted if serverKeygen is true
	PublicKey []byte `json:"publicKey,omitempty"`

	//Pop []byte `json:"POP,omitempty"`

	Groups []string `json:"Groups,omitempty"`

	Ip string `json:"ip,omitempty"`
}

// Response returned by the NEST service to the NEST client
type NebulaCsrResponse struct {
	//The newly generated Nebula Certificate
	NebulaCert cert.NebulaCertificate `json:"NebulaCert"`
	//The newly generated Nebula private key. Omitted if serverKeygen is false on the NebulaCsr
	NebulaPrivateKey []byte `json:"NebulaPrivateKey,omitempty"`
	//The newly generated Nebula configuration file. Omitted for re-enrollment CSRs
	NebulaConf []byte `json:"NebulaConf,omitempty"`
	//The client-local path in which the configuration file and nebula certificate has to be installed
	NebulaPath string `json:"NebulaPath,omitempty"`
}
