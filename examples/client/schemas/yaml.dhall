let types = ../types.dhall

let FirewallConnectionConfig =
      { Type = types.FirewallConnectionConfig
      , default =
        { tcp_timeout = "12m"
        , udp_timeout = "3m"
        , default_timeout = "10m"
        , max_connections = 30000
        }
      }

in  { FirewallConnectionConfig }
