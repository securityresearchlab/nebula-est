package models

import (
	dhall "github.com/philandstuff/dhall-golang/v6/core"
)

type IPv4 struct {
	I1 dhall.NaturalLit `json:"i1" dhall:"i1"`
	I2 dhall.NaturalLit `json:"i2" dhall:"i2"`
	I3 dhall.NaturalLit `json:"i3" dhall:"i3"`
	I4 dhall.NaturalLit `json:"i4" dhall:"i4"`
}

type IPv4WithPort struct {
	I1     dhall.NaturalLit `json:"i1" dhall:"i1"`
	I2     dhall.NaturalLit `json:"i2" dhall:"i2"`
	I3     dhall.NaturalLit `json:"i3" dhall:"i3"`
	I4     dhall.NaturalLit `json:"i4" dhall:"i4"`
	I_port dhall.NaturalLit `json:"i_port" dhall:"i_port"`
}

type IPv4Network struct {
	Mask dhall.NaturalLit `json:"mask" dhall:"mask"`
	In1  dhall.NaturalLit `json:"in1" dhall:"in1"`
	In2  dhall.NaturalLit `json:"in2" dhall:"in2"`
	In3  dhall.NaturalLit `json:"in3" dhall:"in3"`
	In4  dhall.NaturalLit `json:"in4" dhall:"in4"`
}

type IPv4NetworkBoolMapEntry struct {
	MapKeyIB   IPv4Network `json:"mapKeyIB"`
	MapValueIB bool        `json:"mapValueIB"`
}

type TextBoolMapEntry struct {
	MapKeyTB   dhall.PlainTextLit `json:"mapKeyIB" dhall:"mapKeyIB"`
	MapValueTB dhall.BoolLit      `json:"mapValueTB" dhall:"mapValueTB"`
}

type CAName dhall.PlainTextLit

type Directory dhall.PlainTextLit

type Hostname dhall.PlainTextLit

type PkiInfo struct {
	Ca   dhall.PlainTextLit `json:"ca" dhall:"ca"`
	Cert dhall.PlainTextLit `json:"cert" dhall:"cert"`
	Key  dhall.PlainTextLit `json:"key" dhall:"key"`
}

type InterfaceInfo struct {
	Host IPv4             `json:"host" dhall:"host"`
	Port dhall.NaturalLit `json:"port" dhall:"port"`
}

type ListenInfo struct {
	L_host       IPv4             `json:"l_host" dhall:"l_host"`
	L_port       dhall.NaturalLit `json:"l_port" dhall:"l_port"`
	Batch        dhall.NaturalLit `json:"batch,omitempty" dhall:"batch,omitempty"`
	Read_buffer  dhall.NaturalLit `json:"read_buffer,omitempty" dhall:"read_buffer,omitempty"`
	Write_buffer dhall.NaturalLit ` json:"write_buffer,omitempty" dhall:"write_buffer,omitempty"`
}

type DnsConfig struct {
	Dns_interface InterfaceInfo `json:"dns_interface" dhall:"dns_interface"`
}

type IsLighthouseConfig struct {
	Dns DnsConfig `json:"dns,omitempty" dhall:"dns,Optional"`
}

type PunchyInfo struct {
	Punch   dhall.BoolLit      `json:"punch" dhall:"punch"`
	Respond dhall.BoolLit      `json:"respond" dhall:"respond"`
	Delay   dhall.PlainTextLit `json:"delay,omitempty" dhall:"delay,omitempty"`
}

type LocalAllowListInfo struct {
	Interfaces []TextBoolMapEntry        `json:"interfaces,omitempty" dhall:"interfaces,Optional"`
	Cidrs      []IPv4NetworkBoolMapEntry `json:"cidrs,omitempty" dhall:"cidrs,Optional"`
}

type LighthouseInfo struct {
	Interval          dhall.NaturalLit          `json:"interval" dhall:"interval"`
	Remote_allow_list []IPv4NetworkBoolMapEntry `json:"remote_allow_list,omitempty" dhall:"remote_allow_list,Optional"`
	Local_allow_list  LocalAllowListInfo        `json:"local_allow_list,omitempty" dhall:"local_allow_list,Optional"`
}

type SSHDUsers struct {
	User dhall.PlainTextLit   `json:"user" dhall:"user"`
	Keys []dhall.PlainTextLit `json:"keys" dhall:"keys,List"`
}

type SSHDInfo struct {
	Listen           InterfaceInfo      `json:"listen" dhall:"listen"`
	Host_key         dhall.PlainTextLit `json:"host_key" dhall:"host_key"`
	Authorized_users []SSHDUsers        `json:"authorized_users" dhall:"authorized_users,List"`
}

type TunRoute struct {
	S_mtu   dhall.NaturalLit `json:"s_mtu" dhall:"s_mtu"`
	S_route IPv4Network      `json:"s_route" dhall:"s_route"`
}

type UnsafeTunRoute struct {
	U_mtu   dhall.NaturalLit `json:"u_mtu" dhall:"u_mtu"`
	U_route IPv4Network      `json:"u_route" dhall:"u_route"`
	Via     IPv4             `json:"via" dhall:"via"`
}

type TunInfo struct {
	Disabled             dhall.BoolLit      `json:"disabled" dhall:"disabled"`
	Dev                  dhall.PlainTextLit `json:"dev" dhall:"dev"`
	Drop_local_broadcast dhall.BoolLit      `json:"drop_local_broadcast" dhall:"drop_local_broadcast"`
	Drop_multicast       dhall.BoolLit      `json:"drop_multicast" dhall:"drop_multicast"`
	Tx_queue             dhall.NaturalLit   `json:"tx_queue" dhall:"tx_queue"`
	Mtu                  dhall.NaturalLit   `json:"mtu" dhall:"mtu"`
	Routes               []TunRoute         `json:"routes" dhall:"routes,List"`
	Unsafe_routes        []UnsafeTunRoute   `json:"unsafe_routes" dhall:"unsafe_routes,List"`
}

type LogInfo struct {
	Level             dhall.PlainTextLit `json:"level" dhall:"level"`
	Format            dhall.PlainTextLit `json:"format" dhall:"format"`
	Disable_timestamp dhall.BoolLit      `json:"disable_timestamp,omitempty" dhall:"disable_timestamp,omitempty"`
	Timestamp_format  dhall.PlainTextLit `json:"timestamp_format,omitempty" dhall:"timestamp_format,omitempty"`
}

type NebulaHost struct {
	Name              Hostname           `json:"name" dhall:"name"`
	Ip                IPv4               `json:"ip" dhall:"ip"`
	Lighthouse_config IsLighthouseConfig `json:"lighthouse_config,omitempty" dhall:"lighthouse_config,Optional"`
	Pki               PkiInfo            `json:"pki" dhall:"pki"`
	Lighthouse        LighthouseInfo     `json:"lighthouse,omitempty" dhall:"lighthouse"`
	Static_ips        []IPv4WithPort     `json:"static_ips,omitempty" dhall:"static_ips"`
	Listen_interface  ListenInfo         `json:"listen_interface,omitempty" dhall:"listen_interface"`
	Punchy            PunchyInfo         `json:"punchy,omitempty" dhall:"punchy"`
	Logging           LogInfo            `json:"logging,omitempty" dhall:"logging"`
	Tun               TunInfo            `json:"tun,omitempty" dhall:"tun,omitempty"`
	Local_range       dhall.PlainTextLit `json:"local_range,omitempty" dhall:"local_range,Optional"`
	Sshd              SSHDInfo           `json:"sshd,omitempty" dhall:"sshd,Optional"`
	Am_relay          dhall.BoolLit      `json:"am_relay,omitempty" dhall:"am_relay"`
	Use_relays        dhall.BoolLit      `json:"use_relays,omitempty" dhall:"use_relays"`
	Relays            []IPv4             `json:"relays,omitempty" dhall:"relays"`
}
