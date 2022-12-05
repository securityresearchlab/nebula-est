/*
 * Nebula Enrollment over Secure Transport - OpenAPI 3.0
 *
 * This is a simple Public Key Infrastructure Management Server based on the RFC7030 Enrollment over Secure Transport Protocol for a Nebula Mesh Network. The Service accepts requests from TLS connections to create Nebula Certificates for the client (which will be authenticated by providing a secret). The certificate creation is done either by signing client-generated Nebula Public Keys or by generating Nebula key pairs and signing the server-generated Nebula public key and to create Nebula configuration files for the specific client. This Service acts as a Facade for the Nebula CA service (actually signign or creating the Nebula keys) and the Nebula Config service (actually creating the nebula Config. files).
 *
 * API version: 0.3.1
 * Contact: gianmarco.decola@studio.unibo.it
 */
package models

import (
	dhall "github.com/philandstuff/dhall-golang/v6/core"
)

type GroupName dhall.PlainTextLit

type NebulaGroup struct {
	Group_name  GroupName    `json:"group_name" dhall:"group_name"`
	Group_hosts []NebulaHost `json:"group_hosts" dhall:"group_hosts,List"`
}

type RuleDirection dhall.UnionType

type ConnectionTarget dhall.UnionType

type TrafficTarget dhall.UnionType

type PortRange struct {
	R_from dhall.NaturalLit `json:"r_from" dhall:"r_from"`
	R_to   dhall.NaturalLit `json:"r_to" dhall:"r_to"`
}

type Port dhall.UnionType

type Proto dhall.UnionType

type UnidirectionalConnection struct {
	Uc_port  Port               `json:"uc_port" dhall:"uc_port"`
	Uc_proto Proto              `json:"uc_proto" dhall:"uc_proto"`
	From     ConnectionTarget   `json:"from" dhall:"from"`
	To       ConnectionTarget   `json:"to" dhall:"to"`
	Ca_name  dhall.PlainTextLit `json:"ca_name,omitempty" dhall:"ca_name,Optional"`
	Ca_sha   dhall.PlainTextLit `json:"ca_sha,omitempty" dhall:"ca_sha,Optional"`
}

type NebulaConnection struct {
	Connections []UnidirectionalConnection `json:"connections" dhall:"connections,List"`
}

type FirewallRule struct {
	Fr_port        Port               `json:"fr_port" dhall:"fr_port"`
	Fr_proto       Proto              `json:"fr_proto" dhall:"fr_proto"`
	Traffic_target TrafficTarget      `json:"traffic_target" dhall:"traffic_target"`
	Direction      RuleDirection      `json:"direction" dhall:"direction"`
	Fr_ca_name     dhall.PlainTextLit `json:"fr_ca_name,omitempty" dhall:"fr_ca_name,Optional"`
	Fr_ca_sha      dhall.PlainTextLit `json:"fr_ca_sha,omitempty" dhall:"fr_ca_sha,Optional"`
}

type Cipher dhall.UnionType

type NebulaNetwork struct {
	Hosts []NebulaHost `json:"hosts" dhall:"hosts,List"`

	Groups []NebulaGroup `json:"groups" dhall:"groups,List"`

	Connections []NebulaConnection `json:"connections" dhall:"connections,List"`

	Blocklist []dhall.PlainTextLit `json:"blocklist" dhall:"blocklist,List"`

	Cipher Cipher `json:"cipher" dhall:"cipher"`

	IpMask dhall.NaturalLit `json:"ip_mask" dhall:"ip_mask"`
}
