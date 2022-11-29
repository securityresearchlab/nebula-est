/*
 * Nebula Enrollment over Secure Transport - OpenAPI 3.0
 *
 * This is a simple Public Key Infrastructure Management Server based on the RFC7030 Enrollment over Secure Transport Protocol for a Nebula Mesh Network. The Service accepts requests from TLS connections to create Nebula Certificates for the client (which will be authenticated by providing a secret). The certificate creation is done either by signing client-generated Nebula Public Keys or by generating Nebula key pairs and signing the server-generated Nebula public key and to create Nebula configuration files for the specific client. This Service acts as a Facade for the Nebula CA service (actually signign or creating the Nebula keys) and the Nebula Config service (actually creating the nebula Config. files).
 *
 * API version: 0.3.1
 * Contact: gianmarco.decola@studio.unibo.it
 */
package models

type NestAuth struct {
	//The future hostname of the client in the Nebula network
	Hostname string `json:"Hostname,omitempty"`
	//The HMAC of the hostname, to be verified by the NEST service
	Secret []byte `json:"Secret,omitempty"`
}
