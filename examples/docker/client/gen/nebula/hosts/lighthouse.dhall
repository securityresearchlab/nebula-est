let nebula = ../../package.dhall
let lighthouse
: nebula.Host.Type
    = nebula.Host::{
      , name = "lighthouse"
      , ip = nebula.mkIPv4 192 168 90 1
      , lighthouse_config = Some { dns = None nebula.DNSConfig }
      , pki = nebula.mkPkiInfo "/home/pi/nest/lighthouse/config/nebula/" "ca" "lighthouse"
      , static_ips = [ nebula.mkIPv4WithPort 2 224 242 59 4242 ]
      , punchy = nebula.PunchyInfo::{ punch = True, respond = Some True }
      , am_relay = True
      }
in  lighthouse
