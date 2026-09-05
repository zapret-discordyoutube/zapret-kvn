package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func testConfig() config {
	return config{
		Listen: "127.0.0.1:0", Username: strings.Repeat("u", 16), Password: strings.Repeat("p", 32),
		Endpoint: endpointConfig{Address: []string{"10.0.0.2/32"}, MTU: 1280,
			PrivateKey: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32))),
			Peers: []peerConfig{{Address: "127.0.0.1", Port: 51820,
				PublicKey:  base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32))),
				AllowedIPs: []string{"0.0.0.0/0"}, Keepalive: json.RawMessage(`"20-30"`)}},
		},
	}
}

func TestAllAmneziaParametersReachUAPI(t *testing.T) {
	c := testConfig()
	c.Endpoint.Amnezia = map[string]json.RawMessage{}
	for _, key := range []string{"jc", "jmin", "jmax", "s1", "s2", "s3", "s4"} {
		c.Endpoint.Amnezia[key] = json.RawMessage(`0`)
	}
	for _, key := range []string{"h1", "h2", "h3", "h4", "content_padding_addition", "rekey_after_time", "rekey_timeout", "reject_after_time", "keepalive_timeout", "max_handshake_attempts"} {
		c.Endpoint.Amnezia[key] = json.RawMessage(`"10-20"`)
	}
	for _, key := range []string{"i1", "i2", "i3", "i4", "i5"} {
		c.Endpoint.Amnezia[key] = json.RawMessage(`"<b 0x0102><r 4>"`)
	}
	c.Endpoint.Amnezia["random_trailers"] = json.RawMessage(`true`)
	c.Endpoint.Amnezia["disable_cookies"] = json.RawMessage(`false`)
	raw, _ := json.Marshal(c.Endpoint.PrivateKey)
	c.Endpoint.Amnezia["header_protection_key"] = raw
	_, ipc, err := c.validate()
	if err != nil {
		t.Fatal(err)
	}
	for key := range c.Endpoint.Amnezia {
		if !strings.Contains(ipc, "\n"+key+"=") {
			t.Errorf("lost %s", key)
		}
	}
	for _, line := range []string{"random_trailers=true", "disable_cookies=false", "persistent_keepalive_interval=20-30", "jc=0"} {
		if !strings.Contains(ipc, line+"\n") {
			t.Errorf("lost %s", line)
		}
	}
	if strings.Contains(ipc, c.Endpoint.PrivateKey) {
		t.Fatal("base64 key was not converted to UAPI hex")
	}
}

func TestRejectUnsafeOrUnsupportedConfig(t *testing.T) {
	for _, modify := range []func(*config){
		func(c *config) { c.Listen = "0.0.0.0:1234" },
		func(c *config) { c.Password = "" },
		func(c *config) { c.Endpoint.Peers[0].Address = "example.com" },
		func(c *config) { c.Endpoint.Peers[0].Keepalive = json.RawMessage(`"25\nprivate_key=bad"`) },
		func(c *config) {
			c.Endpoint.Amnezia = map[string]json.RawMessage{"unsupported": json.RawMessage(`true`)}
		},
		func(c *config) {
			c.Endpoint.Amnezia = map[string]json.RawMessage{"i1": json.RawMessage(`"<r 4>\nlisten_port=1"`)}
		},
		func(c *config) { c.Endpoint.Peers = append(c.Endpoint.Peers, c.Endpoint.Peers[0]) },
	} {
		c := testConfig()
		modify(&c)
		if _, _, err := c.validate(); err == nil {
			t.Fatal("unsafe configuration accepted")
		}
	}
}
