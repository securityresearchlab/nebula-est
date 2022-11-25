/*
 * Nebula CA service for NEST (Nebula Enrollment over Secure Transport) - OpenAPI 3.0
 *
 * This is a simple Nebula CA service that signs Nebula Public keys and generates Nebula Key Pairs and Certificates on behalf of the NEST service
 *
 * API version: 0.2.1
 * Contact: gianmarco.decola@studio.unibo.it
 */
package nest_ca

import (
	"sync"

	"github.com/m4rkdc/nebula_est/pkg/models"
	"github.com/xgfone/netaddr"
)

type NebulaIpNetwork struct {
	sem            sync.Mutex
	nebula_network netaddr.IPNetwork
}

func (net *NebulaIpNetwork) NewNebulaIpNetwork(network netaddr.IPNetwork) {
	net.sem = sync.Mutex{}
	net.nebula_network = network
	ip := network.Address().String()
	last_char := ip[len(ip)-1:]
	if last_char == "0" {
		net.AddIpNetwork()
	}
}

func (net *NebulaIpNetwork) SetIpNetwork(network netaddr.IPNetwork) {
	net.sem.Lock()
	defer net.sem.Unlock()
	net.nebula_network = network
}

func (net *NebulaIpNetwork) GetIpNetwork() netaddr.IPNetwork {
	net.sem.Lock()
	defer net.sem.Unlock()
	return net.nebula_network
}

func (net *NebulaIpNetwork) AddIpNetwork() netaddr.IPAddress {
	net.sem.Lock()
	defer net.sem.Unlock()

	net.nebula_network = netaddr.MustNewIPNetwork(net.nebula_network.Address().Add(1).String())
	return net.nebula_network.Address()
}

var (
	Certificates_path string = "certificates/"
	Ca_bin            string = "config/bin/nebula-cert"
	Ca_keys_path      string = "config/keys/"
	Log_file          string = "log/nest_ca.log"
	Service_ip        string = "localhost"
	Service_port      string = "5353"
	Ca_name           string = "NEST CA, Inc"
	//Network           net.IPNet = net.IPNet{IP: net.IPv4(192, 168, 100, 0), Mask: net.CIDRMask(24, 32)}
	Network NebulaIpNetwork
)

var Ca_routes = [3]models.Route{
	{
		Name:        "Cacerts",
		Method:      "GET",
		Pattern:     "/cacerts",
		HandlerFunc: Cacerts,
	},
	{
		Name:        "CertificateSign",
		Method:      "POST",
		Pattern:     "/ncsr/sign",
		HandlerFunc: CertificateSign,
	},
	{
		Name:        "GenerateKeys",
		Method:      "POST",
		Pattern:     "/ncsr/generate",
		HandlerFunc: GenerateKeys,
	},
}
