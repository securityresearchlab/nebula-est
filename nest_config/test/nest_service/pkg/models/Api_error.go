/*
 * Nebula Enrollment over Secure Transport - OpenAPI 3.0
 *
 * This is a simple Public Key Infrastructure Management Server based on the RFC7030 Enrollment over Secure Transport Protocol for a Nebula Mesh Network. The Service accepts requests from mutually authenticated TLS-PSK connections to create Nebula Certificates for the client, either by signing client-generated Nebula Public Keys or by generating Nebula key pairs and signing the server-generated Nebula public key and to create Nebula configuration files for the specific client. This Service acts as a Facade for the Nebula CA service (actually signign or creating the Nebula keys) and the Nebula Config service (actually creating the nebula Config. files).
 *
 * API version: 0.1.1
 * Contact: gianmarco.decola@studio.unibo.it
 */
package models

type ApiError struct {
	//HTTP status code
	Code int32 `json:"code"`
	//Error message
	Message string `json:"message"`
}

func (m *ApiError) Error() string {
	return "[Code: " + string(m.Code) + "] " + m.Message
}
