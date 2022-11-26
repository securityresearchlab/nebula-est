/*
 * NEST: Nebula Enrollment over Secure Transport - OpenAPI 3.0
 *
 * This package contains the NEST_CA service routes and their REST API endpoints implementation, along with some service-specific utilities.
 * API version: 0.3.1
 * Contact: gianmarco.decola@studio.unibo.it
 */
package nest_ca

import (
	"sync"

	"github.com/m4rkdc/nebula_est/pkg/models"
	"github.com/xgfone/netaddr"
)

/*
 * The NebulaIpNetwork type holds the future Nebula network Ip(v4|v6) addresses and mask.
 * The current Ip Address can be updated to keep track of the right ip address to impress on the next client Nebula certificate.
 * To do so, a mutex is provided, to insure that all the read/write actions on the nebula_network field are thread-safe.
 */
type NebulaIpNetwork struct {
	sem            sync.Mutex
	nebula_network netaddr.IPNetwork
}

var (
	Certificates_path string = "certificates/"
	Ca_bin            string = "config/bin/nebula-cert"
	Ca_keys_path      string = "config/keys/"
	Log_file          string = "log/nest_ca.log"
	Service_ip        string = "192.168.80.2"
	Service_port      string = "5353"
	Ca_name           string = "NEST CA, Inc"
	Nebula_folder     string = "config/nebula/"
	//Network           net.IPNet = net.IPNet{IP: net.IPv4(192, 168, 100, 0), Mask: net.CIDRMask(24, 32)}
	Network NebulaIpNetwork
)

// The NewNebulaIpNetwork method initializes a new NebulaIpNetwork object
func (net *NebulaIpNetwork) NewNebulaIpNetwork(network netaddr.IPNetwork) {
	net.sem = sync.Mutex{}
	net.nebula_network = network
	ip := network.Address().String()
	last_char := ip[len(ip)-1:]
	if last_char == "0" {
		net.AddIpNetwork()
	}
}

// The SetIpNetwork method atomically sets a new network in the previous NebulaIpNetwork object
func (net *NebulaIpNetwork) SetIpNetwork(network netaddr.IPNetwork) {
	net.sem.Lock()
	defer net.sem.Unlock()
	net.nebula_network = network
}

// The GetIpNetwork method atomically gets the nebula_network field out of the NebulaIpNetwork object
func (net *NebulaIpNetwork) GetIpNetwork() netaddr.IPNetwork {
	net.sem.Lock()
	defer net.sem.Unlock()
	return net.nebula_network
}

// The AddIpNetwork method atomically adds 1 to the numerical value of the current IPAddress on the nebula_network
func (net *NebulaIpNetwork) AddIpNetwork() netaddr.IPAddress {
	net.sem.Lock()
	defer net.sem.Unlock()

	net.nebula_network = netaddr.MustNewIPNetwork(net.nebula_network.Address().Add(1).String())
	return net.nebula_network.Address()
}

/*
For mutual TLS authentication instead of setting up a Nebula tunnel between the nest_ca and nest_service

	func SetupTLS(caCertPool *x509.CertPool) *tls.Config {
	var tls_config = tls.Config{
	MinVersion:               tls.VersionTLS12,
	MaxVersion:               tls.VersionTLS13,
	PreferServerCipherSuites: true,
	ClientAuth:               tls.RequireAndVerifyClientCert,
	CipherSuites: []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	},
	ClientCAs: caCertPool,
	}
	return &tls_config
	}
*/

// Ca_routes contains the routes considered by the nest_ca router
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
