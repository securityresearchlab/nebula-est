let nebula = ../../package.dhall
let lighthouse = ./lighthouse.dhall
let client2
: nebula.Host.Type
    = nebula.Host::{
      , name = "client2"
      , ip = nebula.mkIPv4 192 168 100 3
      , pki = nebula.mkPkiInfo "/home/gio/tesi" "ca" "client2"
      , lighthouse = nebula.LighthouseInfo.default
      , punchy = nebula.PunchyInfo::{ punch = True, respond = Some True }
      , relays = [ lighthouse.ip ]
      }
in client2