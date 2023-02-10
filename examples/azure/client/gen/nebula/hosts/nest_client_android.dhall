let nebula = ../../package.dhall
let lighthouse = ./lighthouse.dhall
let nest_client_android
: nebula.Host.Type
    = nebula.Host::{
      , name = "nest_client_android"
      , ip = nebula.mkIPv4 192 168 90 5
      , pki =
          nebula.mkPkiInfo
            "/home/nest/config/nebula/"
            "ca"
            "nest_client_android"
      , lighthouse = nebula.LighthouseInfo.default
      , punchy = nebula.PunchyInfo::{ punch = True, respond = Some True }
      , relays = [ lighthouse.ip ]
      }
in nest_client_android
