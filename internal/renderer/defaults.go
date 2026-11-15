package renderer

import "encoding/json"

// DirectionDefaults 是某个协议在某个方向上的默认配置模板（面板新建时预填）。
// 模板与各 renderer 的校验/渲染规则对齐：用户点保存即可通过校验、应用即可运行；
// 需要外部输入的字段（服务器地址、证书绑定的域名等）留空字符串占位。
type DirectionDefaults struct {
	Port      int             `json:"port,omitempty"`
	Settings  json.RawMessage `json:"settings,omitempty"`
	TLS       json.RawMessage `json:"tls,omitempty"`
	Transport json.RawMessage `json:"transport,omitempty"`
}

// ProtocolDefaults 是单个协议的入站/出站默认模板集合。
type ProtocolDefaults struct {
	Inbound  *DirectionDefaults `json:"inbound,omitempty"`
	Outbound *DirectionDefaults `json:"outbound,omitempty"`
}

func rawOrNil(s string) json.RawMessage {
	if s == "" {
		return nil
	}
	return json.RawMessage(s)
}

func dir(port int, settings, tls, transport string) *DirectionDefaults {
	return &DirectionDefaults{
		Port:      port,
		Settings:  rawOrNil(settings),
		TLS:       rawOrNil(tls),
		Transport: rawOrNil(transport),
	}
}

// Defaults 返回全部已注册协议的默认配置模板（面板 /api/protocols 一并下发）。
// 入站默认端口按协议区分（vless 443 / vmess 8443 / trojan 4443 / ss 8388 /
// hysteria2 36712 / tuic 10443 / anytls 9443），避免连建多个入站时端口互相冲突；
// 即便撞上已占用端口，service 层新建时也会自动顺延避让。
func Defaults() map[string]ProtocolDefaults {
	return map[string]ProtocolDefaults{
		"vless": {
			// 最主流形态：Reality + vision 流控（私钥由面板调用密钥接口现生成）。
			Inbound: dir(443,
				`{"flow": "xtls-rprx-vision"}`,
				`{"enabled": true, "server_name": "www.microsoft.com", "reality": {"enabled": true, "handshake": {"server": "www.microsoft.com", "server_port": 443}, "private_key": "", "short_id": [""]}}`,
				""),
			Outbound: dir(443,
				`{"server": "", "server_port": 443, "uuid": "", "flow": "xtls-rprx-vision"}`,
				`{"enabled": true, "server_name": "www.microsoft.com", "reality": {"enabled": true, "public_key": "", "short_id": ""}, "utls": {"enabled": true, "fingerprint": "chrome"}}`,
				""),
		},
		"vmess": {
			// 本 renderer 的 vmess 不带 TLS 层，默认 ws 传输（入站无 alter_id 概念）。
			Inbound: dir(8443,
				`{}`,
				"",
				`{"type": "ws", "path": "/vmess", "headers": {"Host": ""}}`),
			Outbound: dir(443,
				`{"server": "", "server_port": 443, "uuid": "", "alter_id": 0}`,
				"",
				`{"type": "ws", "path": "/vmess", "headers": {"Host": ""}}`),
		},
		"trojan": {
			Inbound: dir(4443,
				`{}`,
				`{"enabled": true, "server_name": "", "alpn": ["h2", "http/1.1"]}`,
				""),
			Outbound: dir(443,
				`{"server": "", "server_port": 443, "password": ""}`,
				`{"enabled": true, "server_name": ""}`,
				""),
		},
		"shadowsocks": {
			// 经典加密套件支持多用户（用户入口注入 users[]，无需服务端密码）。
			Inbound: dir(8388,
				`{"method": "aes-128-gcm"}`,
				"",
				""),
			Outbound: dir(8388,
				`{"server": "", "server_port": 8388, "method": "aes-128-gcm", "password": ""}`,
				"",
				""),
		},
		"hysteria2": {
			Inbound: dir(36712,
				`{"up_mbps": 100, "down_mbps": 100}`,
				`{"enabled": true, "server_name": "", "alpn": ["h3"]}`,
				""),
			Outbound: dir(443,
				`{"server": "", "server_port": 443, "password": "", "up_mbps": 100, "down_mbps": 100}`,
				`{"enabled": true, "server_name": "", "alpn": ["h3"]}`,
				""),
		},
		"tuic": {
			Inbound: dir(10443,
				`{"congestion_control": "bbr"}`,
				`{"enabled": true, "server_name": "", "alpn": ["h3"]}`,
				""),
			Outbound: dir(443,
				`{"server": "", "server_port": 443, "uuid": "", "password": "", "congestion_control": "bbr"}`,
				`{"enabled": true, "server_name": "", "alpn": ["h3"]}`,
				""),
		},
		"anytls": {
			Inbound: dir(9443,
				`{}`,
				`{"enabled": true, "server_name": ""}`,
				""),
			Outbound: dir(443,
				`{"server": "", "server_port": 443, "password": ""}`,
				`{"enabled": true, "server_name": ""}`,
				""),
		},
		"direct": {
			Outbound: dir(0, `{}`, "", ""),
		},
		"block": {
			Outbound: dir(0, `{}`, "", ""),
		},
		"selector": {
			Outbound: dir(0, `{"outbounds": ["direct"], "default": "direct"}`, "", ""),
		},
		"urltest": {
			Outbound: dir(0, `{"outbounds": ["direct"], "url": "https://www.gstatic.com/generate_204", "interval": "3m"}`, "", ""),
		},
	}
}
