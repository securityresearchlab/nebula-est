let nebula = ../../package.dhall
let lighthouse = ./lighthouse.dhall
let nest_client_lin_386
: nebula.Host.Type
    = nebula.Host::{
      , name = "nest_client_lin_386"
      , ip = nebula.mkIPv4 192 168 90 4
      , pki =
          nebula.mkPkiInfo
            "/home/nest_client/config/nebula/"
            "ca"
            "nest_client_lin_386"
      , lighthouse = nebula.LighthouseInfo.default
      , punchy = nebula.PunchyInfo::{ punch = True, respond = Some True }
      , relays = [ lighthouse.ip ]
      }
in nest_client_lin_386
