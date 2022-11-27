/*
 * Nebula Enrollment over Secure Transport - OpenAPI 3.0
 *
 * This is a simple Public Key Infrastructure Management Server based on the RFC7030 Enrollment over Secure Transport Protocol for a Nebula Mesh Network. The Service accepts requests from TLS connections to create Nebula Certificates for the client (which will be authenticated by providing a secret). The certificate creation is done either by signing client-generated Nebula Public Keys or by generating Nebula key pairs and signing the server-generated Nebula public key and to create Nebula configuration files for the specific client. This Service acts as a Facade for the Nebula CA service (actually signign or creating the Nebula keys) and the Nebula Config service (actually creating the nebula Config. files).
 *
 * API version: 0.3.1
 * Contact: gianmarco.decola@studio.unibo.it
 */
package models

type GroupName string

type NebulaGroup struct {
	Group_name  GroupName    `json:"group_name"`
	Group_hosts []NebulaHost `json:"group_hosts"`
}

type RuleDirection string

const (
	IN  RuleDirection = "In"
	OUT RuleDirection = "Out"
)

type ConnectionTarget []NebulaHost

type PortRange struct {
	R_from uint32 `json:"r_from"`
	R_to   uint32 `json:"r_to"`
}

type Port PortRange

type Proto string

const (
	ANYPROTO Proto = "any"
	TCP      Proto = "tcp"
	UDP      Proto = "udp"
	ICMP     Proto = "icmp"
)

type UnidirectionalConnection struct {
	Uc_port  Port             `json:"uc_port"`
	Uc_proto Proto            `json:"uc_proto"`
	From     ConnectionTarget `json:"from"`
	To       ConnectionTarget `json:"to"`
	Ca_name  string           `json:"ca_name,omitempty"`
	Ca_sha   string           `json:"ca_sha,omitempty"`
}

type NebulaConnection struct {
	Connections []UnidirectionalConnection `json:"connections"`
}

type Cipher string

const (
	AES        Cipher = "AES"
	Chachapoly Cipher = "Chachapoly"
)

type NebulaNetwork struct {
	Hosts []NebulaHost `json:"hosts"`

	Groups []NebulaGroup `json:"groups"`

	Connections []NebulaConnection `json:"connections"`

	Blocklist []string `json:"blocklist"`

	Cipher Cipher `json:"cipher"`

	IpMask uint32 `json:"ip_mask"`
}
