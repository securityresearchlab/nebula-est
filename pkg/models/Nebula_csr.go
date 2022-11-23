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
  - pop: Proof of Possession of the private key associated to the provided publicKey (random integer sent by the server and encrypted with the private key). Required if publicKey is not empty
*/
type NebulaCsr struct {
	ServerKeygen bool `json:"serverKeygen,omitempty"`

	Rekey bool `json:"rekey,omitempty"`

	Hostname string `json:"hostname"`

	PublicKey []byte `json:"publicKey,omitempty"`

	Pop []byte `json:"POP,omitempty"`
}

type NebulaCsrResponse struct {
	NebulaCert cert.NebulaCertificate `json:"NebulaCert"`

	NebulaConf []byte `json:"NebulaConf,omitempty"`
}
