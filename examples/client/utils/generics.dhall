let types = ../types.dhall

let List/any =
      https://prelude.dhall-lang.org/v21.1.0/List/any
        sha256:b8e9e13b25e799f342a81f6eda4075906eb1a19dfdcb10a0ca25925eba4033b8

let List/filter =
      https://prelude.dhall-lang.org/v21.1.0/List/filter
        sha256:8ebfede5bbfe09675f246c33eb83964880ac615c4b1be8d856076fdbc4b26ba6

let List/map =
      https://prelude.dhall-lang.org/v21.1.0/List/map
        sha256:dd845ffb4568d40327f2a817eb42d1c6138b929ca758d50bc33112ef3c885680

let Map =
      https://prelude.dhall-lang.org/v21.1.0/Map/Type
        sha256:210c7a9eba71efbb0f7a66b3dcf8b9d3976ffc2bc0e907aadfb6aa29c333e8ed

let Map/Entry =
      https://prelude.dhall-lang.org/v21.1.0/Map/Entry
        sha256:f334283bdd9cd88e6ea510ca914bc221fc2dab5fb424d24514b2e0df600d5346

let Natural/equal =
      https://prelude.dhall-lang.org/v21.1.0/Natural/equal
        sha256:7f108edfa35ddc7cebafb24dc073478e93a802e13b5bc3fd22f4768c9b066e60

let showIPv4Network
    : types.IPv4Network -> Text
    = \(n : types.IPv4Network) ->
        "${Natural/show n.in1}.${Natural/show
                                   n.in2}.${Natural/show
                                              n.in3}.${Natural/show
                                                         n.in4}/${Natural/show
                                                                    n.mask}"

let showIPv4
    : types.IPv4 -> Text
    = \(ip : types.IPv4) ->
        "${Natural/show ip.i1}.${Natural/show ip.i2}.${Natural/show
                                                         ip.i3}.${Natural/show
                                                                    ip.i4}"

let showIPv4WithPort
    : types.IPv4WithPort -> Text
    = \(ip : types.IPv4WithPort) ->
        let show_ip
            : Text
            = showIPv4 { i1 = ip.ip1, i2 = ip.ip2, i3 = ip.ip3, i4 = ip.ip4 }

        in  "${show_ip}:${Natural/show ip.i_port}"

let areIPv4Equal
    : types.IPv4 -> types.IPv4 -> Bool
    = \(ip1 : types.IPv4) ->
      \(ip2 : types.IPv4) ->
            Natural/equal ip1.i1 ip2.i1
        &&  Natural/equal ip1.i2 ip2.i2
        &&  Natural/equal ip1.i3 ip2.i3
        &&  Natural/equal ip1.i4 ip2.i4

let isHostInList
    : types.Host -> List types.Host -> Bool
    = \(host : types.Host) ->
      \(list : List types.Host) ->
        List/any
          types.Host
          (\(h : types.Host) -> areIPv4Equal h.ip host.ip)
          list

let isHostInGroup
    : types.Host -> types.Group -> Bool
    = \(host : types.Host) ->
      \(group : types.Group) ->
        isHostInList host group.group_hosts

let isIPInNetwork
    : types.IPv4 -> types.IPv4Network -> Bool
    = \(ip : types.IPv4) -> \(network : types.IPv4Network) -> True

let fromIPv4NetworkBoolMapToMap
    : List types.IPv4NetworkBoolMapEntry -> Map types.IPv4Network Bool
    = \(entries : List types.IPv4NetworkBoolMapEntry) ->
        List/map
          types.IPv4NetworkBoolMapEntry
          (Map/Entry types.IPv4Network Bool)
          ( \(e : types.IPv4NetworkBoolMapEntry) ->
              { mapKey = e.mapKeyIB, mapValue = e.mapValueIB }
          )
          entries

let fromTextBoolMapToMap
    : List types.TextBoolMapEntry -> Map Text Bool
    = \(entries : List types.TextBoolMapEntry) ->
        List/map
          types.TextBoolMapEntry
          (Map/Entry Text Bool)
          ( \(e : types.TextBoolMapEntry) ->
              { mapKey = e.mapKeyTB, mapValue = e.mapValueTB }
          )
          entries

let selectHostFromIP
    : types.Network -> types.IPv4 -> Optional types.Host
    = \(network : types.Network) ->
      \(ip : types.IPv4) ->
        List/head
          types.Host
          ( List/filter
              types.Host
              (\(h : types.Host) -> areIPv4Equal ip h.ip)
              network.hosts
          )

in  { showIPv4Network
    , showIPv4
    , showIPv4WithPort
    , areIPv4Equal
    , isHostInGroup
    , isIPInNetwork
    , fromIPv4NetworkBoolMapToMap
    , fromTextBoolMapToMap
    , selectHostFromIP
    }
