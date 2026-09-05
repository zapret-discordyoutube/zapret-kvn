package main

// This is a transport configuration, not a routing language. Destination DNS
// and direct/proxy/block policy belong exclusively to the sing-box front.
import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

type peerConfig struct {
	Address      string          `json:"address"`
	Port         uint16          `json:"port"`
	PublicKey    string          `json:"public_key"`
	PreSharedKey string          `json:"pre_shared_key,omitempty"`
	AllowedIPs   []string        `json:"allowed_ips"`
	Keepalive    json.RawMessage `json:"persistent_keepalive_interval,omitempty"`
}

type endpointConfig struct {
	Address    []string                   `json:"address"`
	PrivateKey string                     `json:"private_key"`
	MTU        int                        `json:"mtu"`
	ListenPort uint16                     `json:"listen_port,omitempty"`
	Peers      []peerConfig               `json:"peers"`
	Amnezia    map[string]json.RawMessage `json:"amnezia,omitempty"`
}

type config struct {
	Endpoint          endpointConfig `json:"endpoint"`
	Listen            string         `json:"listen"`
	DNSAddress        string         `json:"dns_address,omitempty"`
	BootstrapDNS      []string       `json:"bootstrap_dns,omitempty"`
	Username          string         `json:"username"`
	Password          string         `json:"password"`
	InterfaceIndex    uint32         `json:"interface_index"`
	SessionGeneration uint64         `json:"session_generation"`
	TargetGeneration  uint64         `json:"target_generation"`
	TargetRef         string         `json:"target_ref"`
}

func keyHex(value string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(key) != 32 {
		return "", fmt.Errorf("key must be base64 encoding of exactly 32 bytes")
	}
	return hex.EncodeToString(key), nil
}

// sing-box's native range accepts a number, "from-to", or {from,to}.
// Validate before converting to UAPI so narrowing never wraps uint32 values.
func uint32Range(raw json.RawMessage) (string, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		var n uint32
		if err := json.Unmarshal(raw, &n); err == nil && string(raw) != "null" {
			return strconv.FormatUint(uint64(n), 10), nil
		}
		var bounds struct {
			From *uint32 `json:"from"`
			To   *uint32 `json:"to"`
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&bounds); err != nil || bounds.From == nil || bounds.To == nil || *bounds.From > *bounds.To {
			return "", fmt.Errorf("expected uint32 number or ordered range")
		}
		return fmt.Sprintf("%d-%d", *bounds.From, *bounds.To), nil
	}
	parts := strings.Split(text, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return "", fmt.Errorf("expected uint32 number or ordered range")
	}
	var values []uint64
	for _, part := range parts {
		if part == "" || strings.Trim(part, "0123456789") != "" {
			return "", fmt.Errorf("invalid uint32 range")
		}
		n, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return "", fmt.Errorf("range exceeds uint32")
		}
		values = append(values, n)
	}
	if len(values) == 1 {
		return strconv.FormatUint(values[0], 10), nil
	}
	if values[0] > values[1] {
		return "", fmt.Errorf("reversed uint32 range")
	}
	return fmt.Sprintf("%d-%d", values[0], values[1]), nil
}

func (c config) validate() ([]netip.Addr, string, error) {
	listen, err := netip.ParseAddrPort(c.Listen)
	if err != nil || !listen.Addr().IsLoopback() {
		return nil, "", fmt.Errorf("relay listen must be a literal loopback address")
	}
	if c.DNSAddress != "" {
		dns, err := netip.ParseAddrPort(c.DNSAddress)
		if err != nil || !dns.Addr().IsLoopback() || dns.Port() == 0 {
			return nil, "", fmt.Errorf("DNS delegation requires the sing-box loopback DNS address")
		}
	}
	if len(c.Username) < 16 || len(c.Username) > 255 || len(c.Password) < 32 || len(c.Password) > 255 {
		return nil, "", fmt.Errorf("relay requires per-session credentials (username 16..255, password 32..255 bytes)")
	}
	if c.Endpoint.MTU < 576 || c.Endpoint.MTU > 65535 {
		return nil, "", fmt.Errorf("MTU must be between 576 and 65535")
	}
	var addresses []netip.Addr
	for _, raw := range c.Endpoint.Address {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() {
			return nil, "", fmt.Errorf("invalid tunnel address")
		}
		if prefix.Addr().Is6() && c.Endpoint.MTU < 1280 {
			return nil, "", fmt.Errorf("IPv6 tunnel requires MTU >= 1280")
		}
		addresses = append(addresses, prefix.Addr())
	}
	if len(addresses) == 0 || len(c.Endpoint.Peers) == 0 {
		return nil, "", fmt.Errorf("tunnel addresses and peers are required")
	}
	private, err := keyHex(c.Endpoint.PrivateKey)
	if err != nil {
		return nil, "", fmt.Errorf("private_key: %w", err)
	}
	var ipc strings.Builder
	fmt.Fprintf(&ipc, "private_key=%s\nlisten_port=%d\nreplace_peers=true\n", private, c.Endpoint.ListenPort)
	names := make([]string, 0, len(c.Endpoint.Amnezia))
	for name := range c.Endpoint.Amnezia {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		raw := c.Endpoint.Amnezia[name]
		var value string
		switch name {
		case "jc", "jmin", "jmax", "s1", "s2", "s3", "s4":
			var n uint32
			if err := json.Unmarshal(raw, &n); err != nil {
				return nil, "", fmt.Errorf("%s must be an unsigned integer", name)
			}
			if strings.HasPrefix(name, "s") && n > 65535 {
				return nil, "", fmt.Errorf("%s exceeds uint16", name)
			}
			value = strconv.FormatUint(uint64(n), 10)
		case "h1", "h2", "h3", "h4", "content_padding_addition", "rekey_after_time", "rekey_timeout", "reject_after_time", "keepalive_timeout", "max_handshake_attempts":
			if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
				continue
			}
			value, err = uint32Range(raw)
			if err != nil {
				return nil, "", fmt.Errorf("%s: %w", name, err)
			}
		case "i1", "i2", "i3", "i4", "i5", "header_protection_key":
			if err := json.Unmarshal(raw, &value); err != nil {
				return nil, "", fmt.Errorf("%s must be a string", name)
			}
			if name == "header_protection_key" {
				value, err = keyHex(value)
				if err != nil {
					return nil, "", fmt.Errorf("header_protection_key: %w", err)
				}
			}
		case "random_trailers", "disable_cookies":
			var flag bool
			if err := json.Unmarshal(raw, &flag); err != nil {
				return nil, "", fmt.Errorf("%s must be boolean", name)
			}
			value = strconv.FormatBool(flag)
		default:
			return nil, "", fmt.Errorf("unsupported Amnezia parameter %q", name)
		}
		if strings.ContainsAny(value, "\r\n\x00") {
			return nil, "", fmt.Errorf("invalid control character in %s", name)
		}
		fmt.Fprintf(&ipc, "%s=%s\n", name, value)
	}
	seen := map[string]bool{}
	for _, peer := range c.Endpoint.Peers {
		key, err := keyHex(peer.PublicKey)
		if err != nil {
			return nil, "", fmt.Errorf("public_key: %w", err)
		}
		if seen[key] {
			return nil, "", fmt.Errorf("duplicate peer public_key")
		}
		seen[key] = true
		address, err := netip.ParseAddr(peer.Address)
		if err != nil || address.IsUnspecified() || address.IsMulticast() || peer.Port == 0 {
			return nil, "", fmt.Errorf("peer endpoint must be a resolved unicast IP and nonzero port")
		}
		fmt.Fprintf(&ipc, "public_key=%s\nendpoint=%s\n", key, netip.AddrPortFrom(address, peer.Port))
		if peer.PreSharedKey != "" {
			psk, err := keyHex(peer.PreSharedKey)
			if err != nil {
				return nil, "", fmt.Errorf("pre_shared_key: %w", err)
			}
			fmt.Fprintf(&ipc, "preshared_key=%s\n", psk)
		}
		if len(peer.AllowedIPs) == 0 {
			return nil, "", fmt.Errorf("each peer requires allowed_ips")
		}
		for _, raw := range peer.AllowedIPs {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				return nil, "", fmt.Errorf("invalid allowed_ips prefix")
			}
			fmt.Fprintf(&ipc, "allowed_ip=%s\n", prefix.Masked())
		}
		if len(peer.Keepalive) != 0 && !bytes.Equal(bytes.TrimSpace(peer.Keepalive), []byte("null")) {
			interval, err := uint32Range(peer.Keepalive)
			if err != nil {
				return nil, "", fmt.Errorf("persistent_keepalive_interval: %w", err)
			}
			fmt.Fprintf(&ipc, "persistent_keepalive_interval=%s\n", interval)
		}
	}
	return addresses, ipc.String(), nil
}
