let nebula = ./package.dhall

let lighthouse_ip
    : nebula.IPv4
    = nebula.mkIPv4 192 168 100 1

let ca_name
    : Text
    = "ca"

in  { lighthouse_ip, ca_name }
