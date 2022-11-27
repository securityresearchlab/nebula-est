# NEST: Enrollment over Secure Transport[RFC7030] implementation for Nebula Mesh VPN Certificates

This repo proposes a simple and automated certificate and configuration management system for [Nebula Mesh VPN](https://github.com/slackhq/nebula) certificates, based on the Enrollment over Secure Transport standard [[RFC 7030](https://www.rfc-editor.org/rfc/rfc7030.html)].

## Use Case

A Client who wants to establish a Nebula Mesh VPN has no officially provided way to automatically provision CA signed Nebula certificates and configuration files to the future end nodes of the network. Instead, he/she should rely on manual deployment or secure copy (scp) of such files, implying human intervention is mandatory. The hereby proposed system wants to achieve this distribution in an automated and secure way, insuring an authenticated, tamper-proof and confidential exchange of these crucial files in order to ensure that only the authorized hosts will join the secure Nebula network, using the intended configurations. This system could help set-up a
Nebula Mesh VPN in an Industrial Control System (or IIoT) settings, i.e., deploying the Nebula certs. and configs. on PLCs (programmable logic controllers), SBC (Single Board Computers, i.e., Raspberry Pis) and EWS (Engineering Workstations), to create secure, peer to peer networks between these crucial assets, that will communicate over secure and isolated channels instead of the probably unsecure and unsegregated OT network. It can also help enforce Zero Trust principles by leveraging the identity-based routing and communication infrastructure provided by the Nebula Mesh VPN.

## Installation

To build NEST from source just run

```bash
go build -o ./build ./cmd/*/
```

from the root directory of the project (where the go.mod and go.sum files are).

4 executables will be compiled and saved into the build directory (one for each service and one for the client).

If you want NEST to be installed into the default go folders, go ahead and launch

```bash
go install ./cmd/*/
```

## Documentation

Please check out this module documentation by installing godoc

```bash
go install -v golang.org/x/tools/cmd/godoc@latest
```

and running a local instance of godoc on your system

```bash
godoc -http=127.0.0.1:6060
```

and visiting *http://localhost:6060/pkg/github.com/m4rkdc/nebula_est/* 
