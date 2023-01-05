let connection = ./connection.dhall

let generics = ./generics.dhall

let types = ../types.dhall

let schemas = ../schemas.dhall

let List/map =
      https://prelude.dhall-lang.org/v21.1.0/List/map
        sha256:dd845ffb4568d40327f2a817eb42d1c6138b929ca758d50bc33112ef3c885680

let List/filter =
      https://prelude.dhall-lang.org/v21.1.0/List/filter
        sha256:8ebfede5bbfe09675f246c33eb83964880ac615c4b1be8d856076fdbc4b26ba6

let List/null =
      https://prelude.dhall-lang.org/v21.1.0/List/null
        sha256:2338e39637e9a50d66ae1482c0ed559bbcc11e9442bfca8f8c176bbcd9c4fc80

let Map =
      https://prelude.dhall-lang.org/v21.1.0/Map/Type
        sha256:210c7a9eba71efbb0f7a66b3dcf8b9d3976ffc2bc0e907aadfb6aa29c333e8ed

let Map/empty =
      https://prelude.dhall-lang.org/v21.1.0/Map/empty
        sha256:4c612558b8bbe8f955550ed3fb295d57b1b864c85cd52615b52d0ee0e9682e52

let Map/Entry =
      https://prelude.dhall-lang.org/v21.1.0/Map/Entry
        sha256:f334283bdd9cd88e6ea510ca914bc221fc2dab5fb424d24514b2e0df600d5346

let Optional/map =
      https://prelude.dhall-lang.org/v21.1.0/Optional/map
        sha256:501534192d988218d43261c299cc1d1e0b13d25df388937add784778ab0054fa

let Optional/toList =
      https://prelude.dhall-lang.org/v21.1.0/Optional/toList
        sha256:d78f160c619119ef12389e48a629ce293d69f7624c8d016b7a4767ab400344c4

let rule_map
    : types.FirewallRule -> types.Rule
    = \(rule : types.FirewallRule) ->
        let port
            : types.PortConfig
            = merge
                { Port = \(n : Natural) -> types.PortConfig.Port n
                , AnyPort = types.PortConfig.Description "any"
                , Fragment = types.PortConfig.Description "fragment"
                , Range =
                    \(r : types.PortRange) ->
                      types.PortConfig.Description
                        "${Natural/show r.r_from}-${Natural/show r.r_to}"
                }
                rule.fr_port

        let proto
            : types.ProtoValues
            = merge
                { AnyProto = types.ProtoValues.any
                , ICMP = types.ProtoValues.icmp
                , TCP = types.ProtoValues.tcp
                , UDP = types.ProtoValues.udp
                }
                rule.fr_proto

        let general_info =
              { port
              , proto
              , ca_sha = rule.fr_ca_sha
              , ca_name = rule.fr_ca_name
              }

        let result_rule
            : types.Rule
            = merge
                { AnyHost =
                    types.Rule.HostRule (general_info // { host = "any" })
                , TTHost =
                    \(t : types.Host) ->
                      types.Rule.HostRule
                        (general_info // { host = generics.showIPv4 t.ip })
                , TTGroup =
                    \(g : types.Group) ->
                      types.Rule.GroupRule
                        (general_info // { group = g.group_name })
                , Groups =
                    \(l : List types.Group) ->
                      let groups =
                            List/map
                              types.Group
                              Text
                              (\(g : types.Group) -> g.group_name)
                              l

                      in  types.Rule.GroupsRule (general_info // { groups })
                , TTCidr =
                    \(cidr : types.IPv4Network) ->
                      types.Rule.CIDRRule
                        (     general_info
                          //  { cidr = generics.showIPv4Network cidr }
                        )
                }
                rule.traffic_target

        in  result_rule

let generateLocalAllowListConfig
    : types.LocalAllowListInfo -> types.LocalAllowListConfig
    = \(i : types.LocalAllowListInfo) ->
        let interface_value =
              Optional/map
                (Map Text Bool)
                (Map/Entry Text types.LocalAllowListElement)
                ( \(map : Map Text Bool) ->
                    { mapKey = "interfaces"
                    , mapValue = types.LocalAllowListElement.InterfacesInfo map
                    }
                )
                ( Optional/map
                    (List types.TextBoolMapEntry)
                    (Map Text Bool)
                    generics.fromTextBoolMapToMap
                    i.interfaces
                )

        let interface_elem
            : Map Text types.LocalAllowListElement
            = Optional/toList
                (Map/Entry Text types.LocalAllowListElement)
                interface_value

        let cidr_elems
            : Map Text types.LocalAllowListElement
            = merge
                { Some =
                    \(map : List types.IPv4NetworkBoolMapEntry) ->
                      List/map
                        types.IPv4NetworkBoolMapEntry
                        (Map/Entry Text types.LocalAllowListElement)
                        ( \(entry : types.IPv4NetworkBoolMapEntry) ->
                            { mapKey = generics.showIPv4Network entry.mapKeyIB
                            , mapValue =
                                types.LocalAllowListElement.CIDR
                                  entry.mapValueIB
                            }
                        )
                        map
                , None = Map/empty Text types.LocalAllowListElement
                }
                i.cidrs

        in  interface_elem # cidr_elems

let generateHostConfig
    : types.Network -> types.Host -> types.HostConfig
    = \(network : types.Network) ->
      \(host : types.Host) ->
        let firewall_rules
            : List types.FirewallRule
            = connection.getHostRules network host

        let inbound_rules
            : List types.Rule
            = List/map
                types.FirewallRule
                types.Rule
                rule_map
                ( List/filter
                    types.FirewallRule
                    ( \(rule : types.FirewallRule) ->
                        merge { In = True, Out = False } rule.direction
                    )
                    firewall_rules
                )

        let outbound_rules
            : List types.Rule
            = List/map
                types.FirewallRule
                types.Rule
                rule_map
                ( List/filter
                    types.FirewallRule
                    ( \(rule : types.FirewallRule) ->
                        merge { In = False, Out = True } rule.direction
                    )
                    firewall_rules
                )

        let static_hosts
            : Map Text (List Text)
            = let getStaticIPsAsText
                  : types.Host -> List Text
                  = \(h : types.Host) ->
                      List/map
                        types.IPv4WithPort
                        Text
                        generics.showIPv4WithPort
                        h.static_ips

              in  List/map
                    types.Host
                    (Map/Entry Text (List Text))
                    ( \(h : types.Host) ->
                        { mapKey = generics.showIPv4 h.ip
                        , mapValue = getStaticIPsAsText h
                        }
                    )
                    network.hosts

        let lighthouses_ips
            : List Text
            = List/map
                types.Host
                Text
                (\(h : types.Host) -> generics.showIPv4 h.ip)
                ( List/filter
                    types.Host
                    ( \(host : types.Host) ->
                        merge
                          { Some = \(l : types.IsLighthouseConfig) -> True
                          , None = False
                          }
                          host.lighthouse_config
                    )
                    network.hosts
                )

        let basic_lighthouse_config =
              let lighthouse_base_config =
                    { am_lighthouse = True
                    , interval = host.lighthouse.interval
                    , hosts = [] : List Text
                    }

              in  merge
                    { Some =
                        \(c : types.IsLighthouseConfig) ->
                              lighthouse_base_config
                          //  merge
                                { Some =
                                    \(d : types.DNSConfig) ->
                                      { serve_dns = Some True
                                      , dns = Some
                                        { host =
                                            generics.showIPv4
                                              d.dns_interface.host
                                        , port = d.dns_interface.port
                                        }
                                      }
                                , None =
                                  { serve_dns = None Bool
                                  , dns = None types.ListenConfig
                                  }
                                }
                                c.dns
                    , None =
                      { am_lighthouse = False
                      , interval = host.lighthouse.interval
                      , hosts = lighthouses_ips
                      , serve_dns = None Bool
                      , dns = None types.ListenConfig
                      }
                    }
                    host.lighthouse_config

        let remote_allow_lighthouse_config =
              merge
                { Some =
                    \(map : List types.IPv4NetworkBoolMapEntry) ->
                      let new_map =
                            List/map
                              types.IPv4NetworkBoolMapEntry
                              (Map/Entry Text Bool)
                              ( \(e : types.IPv4NetworkBoolMapEntry) ->
                                  { mapKey = generics.showIPv4Network e.mapKeyIB
                                  , mapValue = e.mapValueIB
                                  }
                              )
                              map

                      in  { remote_allow_list = Some new_map }
                , None.remote_allow_list = None (Map Text Bool)
                }
                host.lighthouse.remote_allow_list

        let local_allow_lighthouse_config =
              { local_allow_list =
                  Optional/map
                    types.LocalAllowListInfo
                    types.LocalAllowListConfig
                    generateLocalAllowListConfig
                    host.lighthouse.local_allow_list
              }

        let lighthouse_config
            : types.LighthouseConfig
            =     basic_lighthouse_config
              //  remote_allow_lighthouse_config
              //  local_allow_lighthouse_config

        let sshd_config
            : Optional types.SSHDConfig
            = merge
                { Some =
                    \(c : types.SSHDInfo) ->
                      Some
                        { enabled = True
                        , listen =
                            "${generics.showIPv4
                                 c.listen.host}:${Natural/show c.listen.port}"
                        , host_key = c.host_key
                        , authorized_users = c.authorized_users
                        }
                , None = None types.SSHDConfig
                }
                host.sshd

        let listen_config
            : types.ListenConfig
            = { host = generics.showIPv4 host.listen_interface.l_host
              , port = host.listen_interface.l_port
              }

        let cipher =
              merge
                { AES = types.CipherValues.aes
                , Chachapoly = types.CipherValues.chachapoly
                }
                network.cipher

        let tun_config =
              let c_routes =
                    List/map
                      types.TunRoute
                      types.TunConfigRoute
                      ( \(r : types.TunRoute) ->
                          { mtu = r.s_mtu
                          , route = generics.showIPv4Network r.s_route
                          }
                      )
                      host.tun.routes

              let c_unsafe_routes =
                    List/map
                      types.TunUnsafeRoute
                      types.TunConfigUnsafeRoute
                      ( \(r : types.TunUnsafeRoute) ->
                          { mtu = r.u_mtu
                          , route = generics.showIPv4Network r.u_route
                          , via = generics.showIPv4 r.via
                          }
                      )
                      host.tun.unsafe_routes

              in      host.tun.{ disabled
                               , dev
                               , drop_local_broadcast
                               , drop_multicast
                               , tx_queue
                               , mtu
                               }
                  //  { routes = c_routes, unsafe_routes = c_unsafe_routes }

        let relay_config =
              { am_relay = host.am_relay
              , use_relays = host.use_relays
              , relays = List/map types.IPv4 Text generics.showIPv4 host.relays
              }

        let pki_config = host.pki // { blocklist = network.blocklist }

        in  { pki = pki_config
            , static_host_map = static_hosts
            , lighthouse = lighthouse_config
            , listen = listen_config
            , punchy = host.punchy
            , tun = tun_config
            , logging = host.logging
            , firewall =
              { conntrack = schemas.FirewallConnectionConfig.default
              , outbound = outbound_rules
              , inbound = inbound_rules
              }
            , cipher
            , local_range = host.local_range
            , sshd = sshd_config
            , relay = relay_config
            }

let configFromIP
    : types.Network -> types.IPv4 -> Optional types.HostConfig
    = \(network : types.Network) ->
      \(ip : types.IPv4) ->
        Optional/map
          types.Host
          types.HostConfig
          (\(host : types.Host) -> generateHostConfig network host)
          (generics.selectHostFromIP network ip)

in  { generateHostConfig, configFromIP }
