let nebula = ../../package.dhall
let lighthouse = ./lighthouse.dhall
let nest_client_win
: nebula.Host.Type
    = nebula.Host::{
      , name = "nest_client_win"
      , ip = nebula.mkIPv4 192 168 90 3
      , pki = 
          nebula.mkPkiInfo 
            "D:\\Uni\\Tesi\\Magistrale\\nest_client_win\\config\\nebula"
            "ca"
            "nest_client_win"
      , lighthouse = nebula.LighthouseInfo.default
      , punchy = nebula.PunchyInfo::{ punch = True, respond = Some True }
      , relays = [ lighthouse.ip ]
      }
in nest_client_win
