let nebula = ../../package.dhall
let lighthouse = ./lighthouse.dhall
let client1
: nebula.Host.Type
    = nebula.Host::{
      , name = "client1"
      , ip = nebula.mkIPv4 192 168 100 2
      , pki =
          nebula.mkPkiInfo
            "C:\\Users\\Giorgia\\Documents\\Universita\\Magistrale-Ingegneria_informatica\\Tesi\\nebula-windows-amd64"
            "ca"
            "client1"
      , lighthouse = nebula.LighthouseInfo.default
      , punchy = nebula.PunchyInfo::{ punch = True, respond = Some True }
      , relays = [ lighthouse.ip ]
      }
in client1