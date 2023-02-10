let types = ./pure.dhall

let Map =
      https://prelude.dhall-lang.org/v21.1.0/Map/Type
        sha256:210c7a9eba71efbb0f7a66b3dcf8b9d3976ffc2bc0e907aadfb6aa29c333e8ed

let PkiConfig
    : Type
    = { ca : Text, cert : Text, key : Text, blocklist : List Text }

let LocalAllowListElement
    : Type
    = < InterfacesInfo : Map Text Bool | CIDR : Bool >

let LocalAllowListConfig
    : Type
    = Map Text LocalAllowListElement

let ListenConfig
    : Type
    = { host : Text, port : Natural }

let LighthouseConfig
    : Type
    = { am_lighthouse : Bool
      , interval : Natural
      , hosts : List Text
      , serve_dns : Optional Bool
      , dns : Optional ListenConfig
      , remote_allow_list : Optional (Map Text Bool)
      , local_allow_list : Optional LocalAllowListConfig
      }

let FirewallConnectionConfig
    : Type
    = { tcp_timeout : Text
      , udp_timeout : Text
      , default_timeout : Text
      , max_connections : Natural
      }

let PortConfig
    : Type
    = < Port : Natural | Description : Text >

let ProtoValues
    : Type
    = < any | icmp | tcp | udp >

let BaseRule
    : Type
    = { port : PortConfig
      , proto : ProtoValues
      , ca_name : Optional Text
      , ca_sha : Optional Text
      }

let CipherValues
    : Type
    = < aes | chachapoly >

let Rule
    : Type
    = < HostRule : BaseRule //\\ { host : Text }
      | GroupRule : BaseRule //\\ { group : Text }
      | GroupsRule : BaseRule //\\ { groups : List Text }
      | CIDRRule : BaseRule //\\ { cidr : Text }
      >

let FirewallConfig
    : Type
    = { conntrack : FirewallConnectionConfig
      , outbound : List Rule
      , inbound : List Rule
      }

let SSHDConfig
    : Type
    = { enabled : Bool
      , listen : Text
      , host_key : Text
      , authorized_users : List types.SSHDUsers
      }

let TunConfigRoute
    : Type
    = { mtu : Natural, route : Text }

let TunConfigUnsafeRoute
    : Type
    = { mtu : Natural, route : Text, via : Text }

let TunConfig
    : Type
    = { disabled : Bool
      , dev : Text
      , drop_local_broadcast : Bool
      , drop_multicast : Bool
      , tx_queue : Natural
      , mtu : Natural
      , routes : List TunConfigRoute
      , unsafe_routes : List TunConfigUnsafeRoute
      }

let RelayConfig
    : Type
    = { relays : List Text, am_relay : Bool, use_relays : Bool }

let HostConfig
    : Type
    = { pki : PkiConfig
      , static_host_map : Map Text (List Text)
      , lighthouse : LighthouseConfig
      , listen : ListenConfig
      , punchy : types.PunchyInfo
      , tun : TunConfig
      , logging : types.LogInfo
      , firewall : FirewallConfig
      , cipher : CipherValues
      , local_range : Optional Text
      , sshd : Optional SSHDConfig
      , relay : RelayConfig
      }

in  { CipherValues
    , FirewallConfig
    , FirewallConnectionConfig
    , HostConfig
    , LighthouseConfig
    , ListenConfig
    , LocalAllowListConfig
    , LocalAllowListElement
    , PkiConfig
    , PortConfig
    , ProtoValues
    , Rule
    , RelayConfig
    , SSHDConfig
    , TunConfig
    , TunConfigUnsafeRoute
    , TunConfigRoute
    }
