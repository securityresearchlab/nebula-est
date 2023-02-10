let Map =
      https://prelude.dhall-lang.org/v21.1.0/Map/Type
        sha256:210c7a9eba71efbb0f7a66b3dcf8b9d3976ffc2bc0e907aadfb6aa29c333e8ed

let types = ../types.dhall

let makes = ../utils/makes.dhall

let PkiInfo =
      { Type = types.PkiInfo
      , default =
        { ca = "/etc/nebula/ca.crt"
        , cert = "/etc/nebula/host.crt"
        , key = "/etc/nebula/host.key"
        }
      }

let LighthouseInfo =
      { Type = types.LighthouseInfo
      , default =
        { interval = 60
        , remote_allow_list = None (List types.IPv4NetworkBoolMapEntry)
        , local_allow_list = None types.LocalAllowListInfo
        }
      }

let InterfaceInfo =
      { Type = types.InterfaceInfo
      , default = { host = makes.mkIPv4 0 0 0 0, port = 4242 }
      }

let ListenInfo =
      { Type = types.ListenInfo
      , default =
        { l_host = makes.mkIPv4 0 0 0 0
        , l_port = 4242
        , batch = None Natural
        , read_buffer = None Natural
        , write_buffer = None Natural
        }
      }

let TunInfo =
      { Type = types.TunInfo
      , default =
        { disabled = False
        , dev = "nebula"
        , drop_local_broadcast = False
        , drop_multicast = False
        , tx_queue = 500
        , mtu = 1300
        , routes = [] : List types.TunRoute
        , unsafe_routes = [] : List types.TunUnsafeRoute
        }
      }

let LogInfo =
      { Type = types.LogInfo
      , default =
        { level = "info"
        , format = "text"
        , disable_timestamp = None Bool
        , timestamp_format = None Text
        }
      }

let PunchyInfo =
      { Type = types.PunchyInfo
      , default = { punch = True, respond = None Bool, delay = None Text }
      }

let Host =
      { Type = types.Host
      , default =
        { lighthouse_config = None types.IsLighthouseConfig
        , pki = PkiInfo.default
        , lighthouse = LighthouseInfo.default
        , static_ips = [] : List types.IPv4WithPort
        , listen_interface = ListenInfo.default
        , punchy = PunchyInfo.default
        , logging = LogInfo.default
        , tun = TunInfo.default
        , sshd = None types.SSHDInfo
        , local_range = None Text
        , am_relay = False
        , relays = [] : List types.IPv4
        , use_relays = True
        }
      }

in  { PkiInfo
    , LighthouseInfo
    , ListenInfo
    , InterfaceInfo
    , TunInfo
    , LogInfo
    , PunchyInfo
    , Host
    }
