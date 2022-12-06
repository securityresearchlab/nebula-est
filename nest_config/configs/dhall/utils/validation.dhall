let connection = ./connection.dhall

let generics = ./generics.dhall

let types = ../types.dhall

let Bool/and =
      https://prelude.dhall-lang.org/v21.1.0/Bool/and
        sha256:0b2114fa33cd76652e4360f012bc082718944fe4c5b28c975483178f8d9b0a6d

let Bool/not =
      https://prelude.dhall-lang.org/v21.1.0/Bool/not
        sha256:723df402df24377d8a853afed08d9d69a0a6d86e2e5b2bac8960b0d4756c7dc4

let List/all =
      https://prelude.dhall-lang.org/v21.1.0/List/all
        sha256:7ac5bb6f77e9ffe9e2356d90968d39764a9a32f75980206e6b12f815bb83dd15

let List/any =
      https://prelude.dhall-lang.org/v21.1.0/List/any
        sha256:b8e9e13b25e799f342a81f6eda4075906eb1a19dfdcb10a0ca25925eba4033b8

let List/concat =
      https://prelude.dhall-lang.org/v21.1.0/List/concat
        sha256:54e43278be13276e03bd1afa89e562e94a0a006377ebea7db14c7562b0de292b

let List/filter =
      https://prelude.dhall-lang.org/v21.1.0/List/filter
        sha256:8ebfede5bbfe09675f246c33eb83964880ac615c4b1be8d856076fdbc4b26ba6

let List/map =
      https://prelude.dhall-lang.org/v21.1.0/List/map
        sha256:dd845ffb4568d40327f2a817eb42d1c6138b929ca758d50bc33112ef3c885680

let List/null =
      https://prelude.dhall-lang.org/v21.1.0/List/null
        sha256:2338e39637e9a50d66ae1482c0ed559bbcc11e9442bfca8f8c176bbcd9c4fc80

let List/partition =
      https://prelude.dhall-lang.org/v21.1.0/List/partition
        sha256:38147ac6d750a6492736dd90cc967bf09aa405c499de943c64fab7b86ae02f03

let Map =
      https://prelude.dhall-lang.org/v21.1.0/Map/Type
        sha256:210c7a9eba71efbb0f7a66b3dcf8b9d3976ffc2bc0e907aadfb6aa29c333e8ed

let Map/values =
      https://prelude.dhall-lang.org/v21.1.0/Map/values
        sha256:ae02cfb06a9307cbecc06130e84fd0c7b96b7f1f11648961e1b030ec00940be8

let Map/keys =
      https://prelude.dhall-lang.org/v21.1.0/Map/keys
        sha256:d13ec34e6acf7c349d82272ef09a37c7bdf37f0dab489e9df47a1ff215d9f5e7

let Natural/equal =
      https://prelude.dhall-lang.org/v21.1.0/Natural/equal
        sha256:7f108edfa35ddc7cebafb24dc073478e93a802e13b5bc3fd22f4768c9b066e60

let Natural/lessThan =
      https://prelude.dhall-lang.org/v21.1.0/Natural/lessThan
        sha256:3381b66749290769badf8855d8a3f4af62e8de52d1364d838a9d1e20c94fa70c

let Natural/lessThanEqual =
      https://prelude.dhall-lang.org/v21.1.0/Natural/lessThanEqual
        sha256:1a5caa2b80a42b9f58fff58e47ac0d9a9946d0b2d36c54034b8ddfe3cb0f3c99

let LocalAllowListChecks
    : Type
    = { cidrs_validites : Bool, interfaces_validities : Bool }

let LighthouseAllowListsChecks
    : Type
    = { remote_list_validities : Bool
      , local_list_validities : LocalAllowListChecks
      }

let TunRoutesChecks
    : Type
    = { unsafe_routes_validities : Bool, routes_validities : Bool }

let HostChecks
    : Type
    = { sshd_validities : Bool
      , ip_validities : Bool
      , static_ips_validity : Bool
      , interfaces_validities : Bool
      , lighthouse_allow_lists_validities : LighthouseAllowListsChecks
      , tun_routes_validites : TunRoutesChecks
      }

let isLighthouse
    : types.Host -> Bool
    = \(host : types.Host) ->
        merge
          { Some = \(config : types.IsLighthouseConfig) -> True, None = False }
          host.lighthouse_config

let areIPsUnique
    : List types.IPv4 -> Bool
    = \(ns : List types.IPv4) ->
        let check_ip
            : types.IPv4 -> Bool
            = \(n : types.IPv4) ->
                Natural/equal
                  ( List/length
                      types.IPv4
                      ( List/partition
                          types.IPv4
                          (\(x : types.IPv4) -> generics.areIPv4Equal n x)
                          ns
                      ).true
                  )
                  1

        let checks = List/map types.IPv4 Bool check_ip ns

        in  Bool/and checks

let validateIPv4
    : types.IPv4 -> Bool
    = \(ip : types.IPv4) ->
        let isNAcceptable
            : Natural -> Bool
            = \(n : Natural) -> Natural/lessThanEqual n 255

        in      isNAcceptable ip.i1
            &&  isNAcceptable ip.i2
            &&  isNAcceptable ip.i3
            &&  isNAcceptable ip.i4

let validateIPv4WithPort
    : types.IPv4WithPort -> Bool
    = \(ip : types.IPv4WithPort) ->
        validateIPv4 { i1 = ip.ip1, i2 = ip.ip2, i3 = ip.ip3, i4 = ip.ip4 }

let validateIPv4Network
    : types.IPv4Network -> Bool
    = \(n : types.IPv4Network) ->
            validateIPv4 { i1 = n.in1, i2 = n.in2, i3 = n.in3, i4 = n.in4 }
        &&  Natural/lessThan n.mask 32

let validateHostInterfaces
    : types.Host -> Bool
    = \(host : types.Host) ->
        let listen_validity = validateIPv4 host.listen_interface.l_host

        let dns_interface_validity =
              merge
                { Some =
                    \(c : types.IsLighthouseConfig) ->
                      merge
                        { Some =
                            \(d : types.DNSConfig) ->
                              validateIPv4 d.dns_interface.host
                        , None = True
                        }
                        c.dns
                , None = True
                }
                host.lighthouse_config

        in  listen_validity && dns_interface_validity

let listValidation
    : Map types.IPv4Network Bool -> Bool
    = \(m : Map types.IPv4Network Bool) ->
        let isDefaultNetwork
            : types.IPv4Network -> Bool
            = \(n : types.IPv4Network) ->
                    Natural/equal n.in1 0
                &&  Natural/equal n.in2 0
                &&  Natural/equal n.in3 0
                &&  Natural/equal n.in4 0
                &&  Natural/equal n.mask 0

        let values = Map/values types.IPv4Network Bool m

        let keys = Map/keys types.IPv4Network Bool m

        let cidrs_validities =
              Bool/and
                (List/map types.IPv4Network Bool validateIPv4Network keys)

        in  if        Bool/and values
                  ||  Bool/and (List/map Bool Bool Bool/not values)
            then  cidrs_validities
            else      cidrs_validities
                  &&  Bool/not
                        ( List/null
                            types.IPv4Network
                            ( List/filter
                                types.IPv4Network
                                isDefaultNetwork
                                keys
                            )
                        )

let validateRemoteAllowList
    : types.Host -> Bool
    = \(host : types.Host) ->
        merge
          { Some =
              \(list : List types.IPv4NetworkBoolMapEntry) ->
                listValidation (generics.fromIPv4NetworkBoolMapToMap list)
          , None = True
          }
          host.lighthouse.remote_allow_list

let validateLocalCIDRAllowLists
    : types.Host -> Bool
    = \(host : types.Host) ->
        let cidrs =
              merge
                { Some =
                    \(info : types.LocalAllowListInfo) ->
                      merge
                        { Some =
                            \(c : List types.IPv4NetworkBoolMapEntry) -> Some c
                        , None = None (List types.IPv4NetworkBoolMapEntry)
                        }
                        info.cidrs
                , None = None (List types.IPv4NetworkBoolMapEntry)
                }
                host.lighthouse.local_allow_list

        let cidrs_validity =
              merge
                { Some =
                    \(list : List types.IPv4NetworkBoolMapEntry) ->
                      listValidation (generics.fromIPv4NetworkBoolMapToMap list)
                , None = True
                }
                cidrs

        in  cidrs_validity

let validateLocalInterfacesAllowLists
    : types.Host -> Bool
    = \(host : types.Host) ->
        let interfaces =
              merge
                { Some =
                    \(info : types.LocalAllowListInfo) ->
                      merge
                        { Some = \(i : List types.TextBoolMapEntry) -> Some i
                        , None = None (List types.TextBoolMapEntry)
                        }
                        info.interfaces
                , None = None (List types.TextBoolMapEntry)
                }
                host.lighthouse.local_allow_list

        in  merge
              { Some =
                  \(list : List types.TextBoolMapEntry) ->
                    let values =
                          List/map
                            types.TextBoolMapEntry
                            Bool
                            (\(e : types.TextBoolMapEntry) -> e.mapValueTB)
                            list

                    in      Bool/and values
                        ||  Bool/and (List/map Bool Bool Bool/not values)
              , None = True
              }
              interfaces

let validateHostSSHD
    : types.Host -> Bool
    = \(host : types.Host) ->
        merge
          { Some =
              \(c : types.SSHDInfo) -> Bool/not (Natural/equal c.listen.port 22)
          , None = True
          }
          host.sshd

let validateHostIPv4
    : types.Host -> Bool
    = \(host : types.Host) -> validateIPv4 host.ip

let validateHostStaticIPv4s
    : types.Host -> Bool
    = \(host : types.Host) ->
        Bool/and
          ( List/map
              types.IPv4WithPort
              Bool
              validateIPv4WithPort
              host.static_ips
          )

let validateHostsAsNetwork
    : List types.Host -> Bool
    = \(hs : List types.Host) ->
        areIPsUnique
          (List/map types.Host types.IPv4 (\(h : types.Host) -> h.ip) hs)

let validateTunUnsafeRoutes
    : types.Host -> Bool
    = \(host : types.Host) ->
        let routes_validities =
              Bool/and
                ( List/map
                    types.TunUnsafeRoute
                    Bool
                    ( \(h : types.TunUnsafeRoute) ->
                        validateIPv4Network h.u_route
                    )
                    host.tun.unsafe_routes
                )

        let vias_validities =
              Bool/and
                ( List/map
                    types.TunUnsafeRoute
                    Bool
                    (\(h : types.TunUnsafeRoute) -> validateIPv4 h.via)
                    host.tun.unsafe_routes
                )

        in  routes_validities && vias_validities

let validateTunRoutes
    : types.Host -> Bool
    = \(host : types.Host) ->
        Bool/and
          ( List/map
              types.TunRoute
              Bool
              (\(h : types.TunRoute) -> validateIPv4Network h.s_route)
              host.tun.routes
          )

let validateSingleHosts
    : List types.Host -> HostChecks
    = \(hs : List types.Host) ->
        { sshd_validities =
            Bool/and (List/map types.Host Bool validateHostSSHD hs)
        , ip_validities =
            Bool/and (List/map types.Host Bool validateHostIPv4 hs)
        , static_ips_validity =
            Bool/and (List/map types.Host Bool validateHostStaticIPv4s hs)
        , interfaces_validities =
            Bool/and (List/map types.Host Bool validateHostInterfaces hs)
        , lighthouse_allow_lists_validities =
          { remote_list_validities =
              Bool/and (List/map types.Host Bool validateRemoteAllowList hs)
          , local_list_validities =
            { cidrs_validites =
                Bool/and
                  (List/map types.Host Bool validateLocalCIDRAllowLists hs)
            , interfaces_validities =
                Bool/and
                  ( List/map
                      types.Host
                      Bool
                      validateLocalInterfacesAllowLists
                      hs
                  )
            }
          }
        , tun_routes_validites =
          { unsafe_routes_validities =
              Bool/and (List/map types.Host Bool validateTunUnsafeRoutes hs)
          , routes_validities =
              Bool/and (List/map types.Host Bool validateTunRoutes hs)
          }
        }

let validateRules
    : List types.FirewallRule -> Bool
    = \(rules : List types.FirewallRule) ->
        List/all
          Bool
          (\(b : Bool) -> b)
          ( List/map
              types.FirewallRule
              Bool
              ( \(rule : types.FirewallRule) ->
                  merge
                    { Port = \(n : Natural) -> True
                    , Range =
                        \(r : types.PortRange) ->
                          Natural/lessThan r.r_from r.r_to
                    , AnyPort = True
                    , Fragment = True
                    }
                    rule.fr_port
              )
              rules
          )

let validateRelays
    : List types.Host -> Bool
    = \(hosts : List types.Host) ->
        let relays =
              List/filter types.Host (\(h : types.Host) -> h.am_relay) hosts

        let using_relays =
              List/filter
                types.Host
                (\(h : types.Host) -> Bool/not (List/null types.IPv4 h.relays))
                hosts

        let checkRelay =
              \(r : types.IPv4) ->
                List/any
                  types.Host
                  (\(h : types.Host) -> generics.areIPv4Equal h.ip r)
                  relays

        let checkRelays =
              \(h : types.Host) -> List/all types.IPv4 checkRelay h.relays

        in  Bool/and (List/map types.Host Bool checkRelays using_relays)

let validate
    : types.Network -> Type
    = \(network : types.Network) ->
        let rules_lists
            : List (List types.FirewallRule)
            = Map/values
                types.Host
                (List types.FirewallRule)
                (connection.getRules network)

        let rules = List/concat types.FirewallRule rules_lists

        let expected =
              { hosts_checks =
                { single_hosts_validity =
                  { sshd_validities = True
                  , ip_validities = True
                  , static_ips_validity = True
                  , interfaces_validities = True
                  , lighthouse_allow_lists_validities =
                    { remote_list_validities = True
                    , local_list_validities =
                      { cidrs_validites = True, interfaces_validities = True }
                    }
                  , tun_routes_validites =
                    { unsafe_routes_validities = True
                    , routes_validities = True
                    }
                  }
                , network_hosts_validity = True
                , lighthouse_present_check = True
                , relays_validity = True
                }
              , rules_checks.rules_check = True
              , network_mask_check = True
              }

        let actual =
              { hosts_checks =
                { single_hosts_validity = validateSingleHosts network.hosts
                , network_hosts_validity = validateHostsAsNetwork network.hosts
                , lighthouse_present_check =
                    List/any types.Host isLighthouse network.hosts
                , relays_validity = validateRelays network.hosts
                }
              , rules_checks.rules_check = validateRules rules
              , network_mask_check = Natural/lessThan network.ip_mask 32
              }

        in  expected === actual

in  { validate }
