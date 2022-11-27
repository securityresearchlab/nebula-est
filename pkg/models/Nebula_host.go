package models

type InterfaceInfo struct {
	Host IPv4   `json:"host"`
	Port uint32 `json:"port"`
}

type DnsConfig struct {
	Dns_interface InterfaceInfo
}

type PkiInfo struct {
	Ca   string `json:"ca"`
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

type ListenInfo struct {
	L_host       IPv4   `json:"l_host"`
	L_port       uint32 `json:"l_port"`
	Batch        uint32 `json:"batch,omitempty"`
	Read_buffer  uint32 `json:"read_buffer,omitempty"`
	Write_buffer uint32 `json:"write_buffer,omitempty"`
}

type IPv4 struct {
	I1 uint32 `json:"i1"`
	I2 uint32 `json:"i2"`
	I3 uint32 `json:"i3"`
	I4 uint32 `json:"i4"`
}

type IPv4WithPort struct {
	I1     uint32 `json:"i1"`
	I2     uint32 `json:"i2"`
	I3     uint32 `json:"i3"`
	I4     uint32 `json:"i4"`
	I_port uint32 `json:"i_port"`
}

type TextBoolMapEntry struct {
	MapKeyTB   string `json:"mapKeyIB"`
	MapValueTB bool   `json:"mapValueTB"`
}

type LocalAllowListInfo struct {
	Interfaces []TextBoolMapEntry        `json:"interfaces,omitempty"`
	Cidrs      []IPv4NetworkBoolMapEntry `json:"cidrs,omitempty"`
}

type LighthouseInfo struct {
	Interval          uint32                    `json:"interval"`
	Remote_allow_list []IPv4NetworkBoolMapEntry `json:"remote_allow_list,omitempty"`
	Local_allow_list  LocalAllowListInfo        `json:"local_allow_list,omitempty"`
}

type IPv4Network struct {
	Mask uint32 `json:"mask"`
	In1  uint32 `json:"in1"`
	In2  uint32 `json:"in2"`
	In3  uint32 `json:"in3"`
	In4  uint32 `json:"in4"`
}

type IPv4NetworkBoolMapEntry struct {
	MapKeyIB   IPv4Network `json:"mapKeyIB"`
	MapValueIB bool        `json:"mapValueIB"`
}

type PunchyInfo struct {
	Punch   bool   `json:"punch"`
	Respond bool   `json:"respond"`
	Delay   string `json:"delay,omitempty"`
}

type LogInfo struct {
	Level             string `json:"level"`
	Format            string `json:"format"`
	Disable_timestamp bool   `json:"disable_timestamp,omitempty"`
	Timestamp_format  string `json:"timestamp_format,omitempty"`
}

type TunRoute struct {
	S_mtu   uint32      `json:"s_mtu"`
	S_route IPv4Network `json:"s_route"`
}

type UnsafeTunRoute struct {
	U_mtu   uint32      `json:"u_mtu"`
	U_route IPv4Network `json:"u_route"`
	Via     IPv4        `json:"via"`
}

type TunInfo struct {
	Disabled             bool             `json:"disabled"`
	Dev                  string           `json:"dev"`
	Drop_local_broadcast bool             `json:"drop_local_broadcast"`
	Drop_multicast       bool             `json:"drop_multicast"`
	Tx_queue             uint32           `json:"tx_queue"`
	Mtu                  uint32           `json:"mtu"`
	Routes               []TunRoute       `json:"routes"`
	Unsafe_routes        []UnsafeTunRoute `json:"unsafe_routes"`
}

type SSHDUsers struct {
	User string   `json:"user"`
	Keys []string `json:"keys"`
}

type SSHDInfo struct {
	Listen           InterfaceInfo `json:"listen"`
	Host_key         string        `json:"host_key"`
	Authorized_users []SSHDUsers   `json:"authorized_users"`
}

type Hostname struct {
	Name string
}

type NebulaHost struct {
	Name              Hostname       `json:"name"`
	Ip                IPv4           `json:"ip"`
	Lighthouse_config DnsConfig      `json:"lighthouse_config,omitempty"`
	Pki               PkiInfo        `json:"pki"`
	Lighthouse        LighthouseInfo `json:"lighthouse,omitempty"`
	Static_ips        []IPv4WithPort `json:"static_ips,omitempty"`
	Listen_interface  ListenInfo     `json:"listen_interface,omitempty"`
	Punchy            PunchyInfo     `json:"punchy,omitempty"`
	Logging           LogInfo        `json:"logging,omitempty"`
	Tun               TunInfo        `json:"tun,omitempty"`
	Local_range       string         `json:"local_range,omitempty"`
	Sshd              SSHDInfo       `json:"sshd,omitempty"`
	Am_relay          bool           `json:"am_relay,omitempty"`
	Use_relays        bool           `json:"use_relays,omitempty"`
	Relays            []IPv4         `json:"relays,omitempty"`
}
