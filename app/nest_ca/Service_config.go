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
	"crypto/tls"
	"crypto/x509"
	"sync"

	"github.com/m4rkdc/nebula_est/pkg/models"
	"github.com/xgfone/netaddr"
)

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
