package logic

import (
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/go-playground/assert/v2"
	nest_ca "github.com/m4rkdc/nebula_est/nest_ca/pkg/logic"
	nest_config "github.com/m4rkdc/nebula_est/nest_config/pkg/logic"
	nest_service "github.com/m4rkdc/nebula_est/nest_service/pkg/logic"
	"github.com/m4rkdc/nebula_est/nest_service/pkg/models"
	"github.com/m4rkdc/nebula_est/nest_service/pkg/utils"
	nest_test "github.com/m4rkdc/nebula_est/nest_service/test"
	"github.com/slackhq/nebula/cert"
)

func TestGetCACerts(t *testing.T) {
	var (
		endpoint models.Route = nest_service.Service_routes[0]
	)

	r := nest_test.MockRouterForEndpoint(&endpoint)
	utils.Ca_cert_file = "../../../nest_service/test/config/ca.crt"
	utils.Service_ip = "localhost"
	utils.Service_port = "8087"
	Nest_service_ip = utils.Service_ip
	Nest_service_port = utils.Service_port
	Nest_certificate = "../../../nest_service/test/config/tls/nest_service-crt.pem"
	go r.RunTLS(utils.Service_ip+":"+utils.Service_port, "../../../nest_service/test/config/tls/nest_service-crt.pem", "../../../nest_service/test/config/tls/nest_service-key.pem")
	err := GetCACerts()
	assert.Equal(t, err, nil)
	b, _ := os.ReadFile(utils.Ca_cert_file)
	var ca_certs []cert.NebulaCertificate
	for {
		cert, b, _ := cert.UnmarshalNebulaCertificateFromPEM(b)
		if cert == nil {
			break
		}
		ca_certs = append(ca_certs, *cert)
		if len(b) == 0 {
			break
		}
	}
	b, err = os.ReadFile("ca.crt")
	assert.Equal(t, err, nil)
	cert, _, _ := cert.UnmarshalNebulaCertificateFromPEM(b)
	assert.Equal(t, cert.Signature, ca_certs[0].Signature)
}

func TestAutorizeHost(t *testing.T) {
	var (
		endpoint models.Route = nest_service.Service_routes[1]
	)

	r := nest_test.MockRouterForEndpoint(&endpoint)
	utils.Hostnames_file = "../../../nest_service/test/config/hostnames"
	utils.Service_ip = "localhost"
	utils.Service_port = "8088"
	Nest_service_ip = utils.Service_ip
	Nest_service_port = utils.Service_port
	Nest_certificate = "../../../nest_service/test/config/tls/nest_service-crt.pem"
	utils.HMAC_key = "../../../nest_service/test/config/hmac.key"
	utils.Ncsr_folder = "../../../nest_service/test/ncsr/"
	go r.RunTLS(utils.Service_ip+":"+utils.Service_port, "../../../nest_service/test/config/tls/nest_service-crt.pem", "../../../nest_service/test/config/tls/nest_service-key.pem")
	Nebula_auth = "../../test/secret.hmac"
	Hostname = "lighthouse"
	err := AuthorizeHost()
	assert.Equal(t, err, nil)
}

func TestEnroll(t *testing.T) {
	var (
		service_endpoint models.Route = nest_service.Service_routes[2]
		ca_endpoint      models.Route = nest_ca.Ca_routes[1]
		config_endpoint  models.Route = nest_config.Conf_routes[1]
	)
	r := nest_test.MockRouterForEndpoint(&service_endpoint)
	r2 := nest_test.MockRouterForEndpoint(&ca_endpoint)
	r3 := nest_test.MockRouterForEndpoint(&config_endpoint)
	utils.Hostnames_file = "../../../nest_service/test/config/hostnames"
	utils.Service_ip = "localhost"
	utils.Service_port = "8089"
	utils.Ca_service_ip = "localhost"
	utils.Ca_service_port = "8090"
	utils.Conf_service_ip = "localhost"
	utils.Conf_service_port = "8091"
	Nest_service_ip = utils.Service_ip
	Nest_service_port = utils.Service_port
	Bin_folder = "../../test/"
	Nest_certificate = "../../../nest_service/test/config/tls/nest_service-crt.pem"
	utils.Ncsr_folder = "../../../nest_service/test/ncsr/"
	go r.RunTLS(utils.Service_ip+":"+utils.Service_port, "../../../nest_service/test/config/tls/nest_service-crt.pem", "../../../nest_service/test/config/tls/nest_service-key.pem")
	Hostname = "lighthouse"
	utils.Certificates_path = "../../../nest_ca/test/certificates/"
	os.Remove(utils.Certificates_path + Hostname + ".crt")
	utils.Ca_bin = "../../../nest_ca/test/config/bin/nebula-cert"
	utils.Ca_keys_path = "../../../nest_ca/test/config/keys/"
	go r2.Run(utils.Ca_service_ip + ":" + utils.Ca_service_port)
	utils.Dhall_dir = "../../../nest_config/test/dhall/"
	utils.Dhall_configuration = utils.Dhall_dir + "nebula/nebula_conf.dhall"

	go r3.Run(utils.Conf_service_ip + ":" + utils.Conf_service_port)
	go Enroll()
	var br bool
	for !br {
		select {
		case duration := <-Enroll_chan:
			assert.Equal(t, duration < 0, false)
			br = true
		default:
			continue
		}
	}
	b, err := os.ReadFile("ncsr_status")
	assert.Equal(t, err, nil)
	ok, err := regexp.Match("Completed", b)
	assert.Equal(t, err, nil)
	assert.Equal(t, ok, true)
	Nebula_conf_folder = "../../test/"
	_, err = os.Stat(Nebula_conf_folder + Hostname + ".crt")
	assert.Equal(t, os.IsNotExist(err), false)
	_, err = os.Stat(Nebula_conf_folder + "ca.crt")
	assert.Equal(t, os.IsNotExist(err), false)
	_, err = os.Stat(Nebula_conf_folder + Hostname + ".key")
	assert.Equal(t, os.IsNotExist(err), false)
	_, err = os.Stat(Nebula_conf_folder + "config.yml")
	assert.Equal(t, os.IsNotExist(err), false)
}

func TestServerKeygen(t *testing.T) {
	var (
		service_endpoint models.Route = nest_service.Service_routes[5]
		ca_endpoint      models.Route = nest_ca.Ca_routes[2]
		config_endpoint  models.Route = nest_config.Conf_routes[1]
	)
	r := nest_test.MockRouterForEndpoint(&service_endpoint)
	r2 := nest_test.MockRouterForEndpoint(&ca_endpoint)
	r3 := nest_test.MockRouterForEndpoint(&config_endpoint)
	utils.Hostnames_file = "../../../nest_service/test/config/hostnames"
	utils.Service_ip = "localhost"
	utils.Service_port = "8092"
	utils.Ca_service_ip = "localhost"
	utils.Ca_service_port = "8093"
	utils.Conf_service_ip = "localhost"
	utils.Conf_service_port = "8094"
	Nest_service_ip = utils.Service_ip
	Nest_service_port = utils.Service_port
	Bin_folder = "../../test/"
	Nest_certificate = "../../../nest_service/test/config/tls/nest_service-crt.pem"
	utils.Ncsr_folder = "../../../nest_service/test/ncsr/"
	go r.RunTLS(utils.Service_ip+":"+utils.Service_port, "../../../nest_service/test/config/tls/nest_service-crt.pem", "../../../nest_service/test/config/tls/nest_service-key.pem")
	Hostname = "lighthouse"
	os.WriteFile(utils.Ncsr_folder+Hostname, []byte("Pending"), 0600)
	utils.Certificates_path = "../../../nest_ca/test/certificates/"
	os.Remove(utils.Certificates_path + Hostname + ".crt")
	utils.Ca_bin = "../../../nest_ca/test/config/bin/nebula-cert"
	utils.Ca_keys_path = "../../../nest_ca/test/config/keys/"
	go r2.Run(utils.Ca_service_ip + ":" + utils.Ca_service_port)
	utils.Dhall_dir = "../../../nest_config/test/dhall/"
	utils.Dhall_configuration = utils.Dhall_dir + "nebula/nebula_conf.dhall"

	go r3.Run(utils.Conf_service_ip + ":" + utils.Conf_service_port)
	go ServerKeygen()
	var br bool
	for !br {
		select {
		case duration := <-Enroll_chan:
			assert.Equal(t, duration < 0, false)
			br = true
		default:
			continue
		}
	}
	b, err := os.ReadFile("ncsr_status")
	assert.Equal(t, err, nil)
	ok, err := regexp.Match("Completed", b)
	assert.Equal(t, err, nil)
	assert.Equal(t, ok, true)
	Nebula_conf_folder = "../../test/"
	_, err = os.Stat(Nebula_conf_folder + Hostname + ".crt")
	assert.Equal(t, os.IsNotExist(err), false)
	_, err = os.Stat(Nebula_conf_folder + "ca.crt")
	assert.Equal(t, os.IsNotExist(err), false)
	_, err = os.Stat(Nebula_conf_folder + Hostname + ".key")
	assert.Equal(t, os.IsNotExist(err), false)
	_, err = os.Stat(Nebula_conf_folder + "config.yml")
	assert.Equal(t, os.IsNotExist(err), false)
}

func TestReenroll(t *testing.T) {
	var (
		service_endpoint models.Route = nest_service.Service_routes[4]
		ca_endpoint      models.Route = nest_ca.Ca_routes[1]
	)
	r := nest_test.MockRouterForEndpoint(&service_endpoint)
	r2 := nest_test.MockRouterForEndpoint(&ca_endpoint)
	utils.Hostnames_file = "../../../nest_service/test/config/hostnames"
	utils.Service_ip = "localhost"
	utils.Service_port = "8095"
	utils.Ca_service_ip = "localhost"
	utils.Ca_service_port = "8096"
	Nest_service_ip = utils.Service_ip
	Nest_service_port = utils.Service_port
	Bin_folder = "../../test/"
	Nest_certificate = "../../../nest_service/test/config/tls/nest_service-crt.pem"
	utils.Ncsr_folder = "../../../nest_service/test/ncsr/"
	go r.RunTLS(utils.Service_ip+":"+utils.Service_port, "../../../nest_service/test/config/tls/nest_service-crt.pem", "../../../nest_service/test/config/tls/nest_service-key.pem")
	Hostname = "lighthouse"
	utils.Certificates_path = "../../../nest_ca/test/certificates/"
	utils.Ca_bin = "../../../nest_ca/test/config/bin/nebula-cert"
	utils.Ca_keys_path = "../../../nest_ca/test/config/keys/"
	go r2.Run(utils.Ca_service_ip + ":" + utils.Ca_service_port)
	Nebula_conf_folder = "../../test/"
	info, _ := os.Stat(Nebula_conf_folder + Hostname + ".crt")
	last_time := info.ModTime()
	go Reenroll()
	var br bool
	for !br {
		select {
		case duration := <-Enroll_chan:
			assert.Equal(t, duration < 0, false)
			br = true
		default:
			continue
		}
	}
	b, err := os.ReadFile("ncsr_status")
	assert.Equal(t, err, nil)
	ok, err := regexp.Match("Completed", b)
	assert.Equal(t, err, nil)
	assert.Equal(t, ok, true)
	Nebula_conf_folder = "../../test/"
	info, err = os.Stat(Nebula_conf_folder + Hostname + ".crt")
	assert.Equal(t, os.IsNotExist(err), false)
	assert.NotEqual(t, info.ModTime(), last_time)
	last_time = info.ModTime()

	info, _ = os.Stat(Nebula_conf_folder + Hostname + ".key")
	last_time_key := info.ModTime()

	Rekey = true
	go Reenroll()
	br = false
	for !br {
		select {
		case duration := <-Enroll_chan:
			assert.Equal(t, duration < 0, false)
			br = true
		default:
			continue
		}
	}
	b, err = os.ReadFile("ncsr_status")
	assert.Equal(t, err, nil)
	ok, err = regexp.Match("Completed", b)
	assert.Equal(t, err, nil)
	assert.Equal(t, ok, true)
	Nebula_conf_folder = "../../test/"
	info, _ = os.Stat(Nebula_conf_folder + Hostname + ".crt")
	assert.NotEqual(t, info.ModTime(), last_time)
	last_time = info.ModTime()
	info, _ = os.Stat(Nebula_conf_folder + Hostname + ".key")
	assert.NotEqual(t, info.ModTime(), last_time_key)
	last_time_key = info.ModTime()

	Bin_folder = "./"
	ca_endpoint = nest_ca.Ca_routes[2]
	r2 = nest_test.MockRouterForEndpoint(&ca_endpoint)
	utils.Ca_service_port = "8097"
	go r2.Run(utils.Ca_service_ip + ":" + utils.Ca_service_port)
	Nebula_conf_folder = "../../test/"
	go Reenroll()
	br = false
	for !br {
		select {
		case duration := <-Enroll_chan:
			assert.Equal(t, duration < 0, false)
			br = true
		default:
			continue
		}
	}
	b, err = os.ReadFile("ncsr_status")
	assert.Equal(t, err, nil)
	ok, err = regexp.Match("Completed", b)
	assert.Equal(t, err, nil)
	assert.Equal(t, ok, true)
	Nebula_conf_folder = "../../test/"
	info, _ = os.Stat(Nebula_conf_folder + Hostname + ".crt")
	assert.NotEqual(t, info.ModTime(), last_time)
	last_time = info.ModTime()
	info, _ = os.Stat(Nebula_conf_folder + Hostname + ".key")
	assert.NotEqual(t, info.ModTime(), last_time_key)
	last_time_key = info.ModTime()
	go sendDuration()
	Nebula_conf_folder = "../../test/"
	Rekey = false
	utils.Ca_service_port = "8096"
	br = false
	for !br {
		select {
		case duration := <-Enroll_chan:
			time.AfterFunc(duration, Reenroll)
			br = true
		default:
			continue
		}
	}
	time.Sleep(1 * time.Second)
	info, _ = os.Stat(Nebula_conf_folder + Hostname + ".crt")
	assert.NotEqual(t, info.ModTime(), last_time)
	info, _ = os.Stat(Nebula_conf_folder + Hostname + ".key")
	assert.Equal(t, info.ModTime(), last_time_key)
	os.Remove(Nebula_conf_folder + "ca.crt")
	os.Remove(Nebula_conf_folder + "config.yml")
	os.Remove(Nebula_conf_folder + "lighthouse.crt")
	os.Remove(Nebula_conf_folder + "lighthouse.key")
	os.Remove(Nebula_conf_folder + "lighthouse.yml")
	os.Remove(utils.Certificates_path + "lighthouse.crt")
	os.Remove(utils.Ncsr_folder + "lighthouse")
	os.Remove("ncsr_status")
}

func sendDuration() {
	Enroll_chan <- 2 * time.Millisecond
}
