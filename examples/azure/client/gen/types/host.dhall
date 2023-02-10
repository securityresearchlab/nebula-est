let Map =
      https://prelude.dhall-lang.org/v21.1.0/Map/Type
        sha256:210c7a9eba71efbb0f7a66b3dcf8b9d3976ffc2bc0e907aadfb6aa29c333e8ed

let IPv4
    : Type
    = { i1 : Natural, i2 : Natural, i3 : Natural, i4 : Natural }

let IPv4WithPort
    : Type
    = { ip1 : Natural
      , ip2 : Natural
      , ip3 : Natural
      , ip4 : Natural
      , i_port : Natural
      }

let IPv4Network =
      { mask : Natural
      , in1 : Natural
      , in2 : Natural
      , in3 : Natural
      , in4 : Natural
      }

let IPv4NetworkBoolMapEntry
    : Type
    = { mapKeyIB : IPv4Network, mapValueIB : Bool }

let TextBoolMapEntry
    : Type
    = { mapKeyTB : Text, mapValueTB : Bool }

let CAName
    : Type
    = Text

let Directory
    : Type
    = Text

let HostName
    : Type
    = Text

let PkiInfo
    : Type
    = { ca : Text, cert : Text, key : Text }

let InterfaceInfo
    : Type
    = { host : IPv4, port : Natural }

let ListenInfo
    : Type
    = { l_host : IPv4
      , l_port : Natural
      , batch : Optional Natural
      , read_buffer : Optional Natural
      , write_buffer : Optional Natural
      }

let DNSConfig
    : Type
    = { dns_interface : InterfaceInfo }

let IsLighthouseConfig
    : Type
    = { dns : Optional DNSConfig }

let PunchyInfo
    : Type
    = { punch : Bool, respond : Optional Bool, delay : Optional Text }

let LocalAllowListInfo
    : Type
    = { interfaces : Optional (List TextBoolMapEntry)
      , cidrs : Optional (List IPv4NetworkBoolMapEntry)
      }

let LighthouseInfo
    : Type
    = { interval : Natural
      , remote_allow_list : Optional (List IPv4NetworkBoolMapEntry)
      , local_allow_list : Optional LocalAllowListInfo
      }

let SSHDUsers
    : Type
    = { user : Text, keys : List Text }

let SSHDInfo
    : Type
    = { listen : InterfaceInfo
      , host_key : Text
      , authorized_users : List SSHDUsers
      }

let TunRoute
    : Type
    = { s_mtu : Natural, s_route : IPv4Network }

let TunUnsafeRoute
    : Type
    = { u_mtu : Natural, u_route : IPv4Network, via : IPv4 }

let TunInfo
    : Type
    = { disabled : Bool
      , dev : Text
      , drop_local_broadcast : Bool
      , drop_multicast : Bool
      , tx_queue : Natural
      , mtu : Natural
      , routes : List TunRoute
      , unsafe_routes : List TunUnsafeRoute
      }

let LogInfo
    : Type
    = { level : Text
      , format : Text
      , disable_timestamp : Optional Bool
      , timestamp_format : Optional Text
      }

let Host
    : Type
    = { name : HostName
      , ip : IPv4
      , lighthouse_config : Optional IsLighthouseConfig
      , pki : PkiInfo
      , lighthouse : LighthouseInfo
      , static_ips : List IPv4WithPort
      , listen_interface : ListenInfo
      , punchy : PunchyInfo
      , logging : LogInfo
      , tun : TunInfo
      , local_range : Optional Text
      , sshd : Optional SSHDInfo
      , am_relay : Bool
      , use_relays : Bool
      , relays : List IPv4
      }

in  { IPv4
    , IPv4WithPort
    , IPv4Network
    , IPv4NetworkBoolMapEntry
    , TextBoolMapEntry
    , CAName
    , Directory
    , HostName
    , PkiInfo
    , DNSConfig
    , IsLighthouseConfig
    , PunchyInfo
    , LocalAllowListInfo
    , LighthouseInfo
    , SSHDUsers
    , SSHDInfo
    , InterfaceInfo
    , ListenInfo
    , TunInfo
    , TunRoute
    , TunUnsafeRoute
    , LogInfo
    , Host
    }
