/*
 * Nebula CA service for NEST (Nebula Enrollment over Secure Transport) - OpenAPI 3.0
 *
 * This is a simple Nebula CA service that signs Nebula Public keys and generates Nebula Key Pairs and Certificates on behalf of the NEST service
 *
 * API version: 0.2.1
 * Contact: gianmarco.decola@studio.unibo.it
 */
package models

import (
	"github.com/slackhq/nebula/cert"
)

// Response returned by the Nebula CA to the NEST service
type CaResponse struct {
	//The newly generated Nebula Certificate
	NebulaCert cert.NebulaCertificate `json:"NebulaCert"`
	//The newly generated Nebula private key. Omitted if serverKeygen is false on the NebulaCsr
	NebulaPrivateKey []byte `json:"NebulaPrivateKey,omitempty"`
}
