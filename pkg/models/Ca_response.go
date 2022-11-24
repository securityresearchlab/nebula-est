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

type CaResponse struct {
	NebulaCert cert.NebulaCertificate `json:"NebulaCert"`

	NebulaPrivateKey []byte `json:"NebulaPrivateKey,omitempty"`
}
