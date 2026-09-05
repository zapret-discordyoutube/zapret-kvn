package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

const maxConfigBytes = 1024 * 1024

type journal struct {
	mu      sync.Mutex
	config  config
	secrets []string
}

func newJournal(c config) *journal {
	j := &journal{config: c, secrets: []string{c.Username, c.Password, c.Endpoint.PrivateKey}}
	for _, p := range c.Endpoint.Peers {
		j.secrets = append(j.secrets, p.PublicKey, p.PreSharedKey)
	}
	var hpk string
	_ = json.Unmarshal(c.Endpoint.Amnezia["header_protection_key"], &hpk)
	j.secrets = append(j.secrets, hpk)
	for _, secret := range append([]string{}, j.secrets...) {
		if value, err := keyHex(secret); err == nil {
			j.secrets = append(j.secrets, value)
		}
	}
	return j
}

func (j *journal) emit(stage, raw string, fields map[string]any) {
	for _, secret := range j.secrets {
		if len(secret) >= 4 {
			raw = strings.ReplaceAll(raw, secret, "<redacted>")
		}
	}
	if fields == nil {
		fields = map[string]any{}
	}
	fields["stage"], fields["raw"] = stage, raw
	fields["session_generation"], fields["target_generation"] = j.config.SessionGeneration, j.config.TargetGeneration
	fields["target_ref"], fields["timestamp"] = j.config.TargetRef, time.Now().UTC().Format(time.RFC3339Nano)
	j.mu.Lock()
	defer j.mu.Unlock()
	_ = json.NewEncoder(os.Stdout).Encode(fields)
}

func coreVersion() string {
	if build, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range build.Deps {
			if dep.Path == "github.com/amnezia-vpn/amneziawg-go/v3" {
				return dep.Version
			}
		}
	}
	return "unknown"
}

// A single bounded JSON line travels over the inherited private stdin pipe.
// The pipe stays open as the parent-lifetime lease: EOF always tears down core.
func run() error {
	reader := bufio.NewReader(io.LimitReader(os.Stdin, maxConfigBytes+1))
	line, err := reader.ReadBytes('\n')
	if err != nil || len(line) > maxConfigBytes {
		return fmt.Errorf("expected bounded JSON configuration line on stdin")
	}
	var c config
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&c); err != nil {
		return fmt.Errorf("invalid transport configuration: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("unexpected trailing configuration")
	}
	j := newJournal(c)
	if err := bootstrapPeers(&c); err != nil {
		j.emit("bootstrap_dns", err.Error(), nil)
		return errReported
	}
	addresses, ipc, err := c.validate()
	if err != nil {
		j.emit("configure", err.Error(), nil)
		return errReported
	}
	tun, stack, err := netstack.CreateNetTUN(addresses, nil, c.Endpoint.MTU)
	if err != nil {
		j.emit("netstack", err.Error(), nil)
		return errReported
	}
	logger := &device.Logger{
		Verbosef: func(format string, args ...any) { j.emit("core", fmt.Sprintf(format, args...), nil) },
		Errorf:   func(format string, args ...any) { j.emit("core_error", fmt.Sprintf(format, args...), nil) },
	}
	core := device.NewDevice(tun, newProtectedBind(c), logger)
	defer core.Close()
	core.DisableSomeRoamingForBrokenMobileSemantics()
	if err := core.IpcSet(ipc); err != nil {
		j.emit("configure", err.Error(), nil)
		return errReported
	}
	if err := core.Up(); err != nil {
		j.emit("start", err.Error(), nil)
		return errReported
	}
	listener, err := net.Listen("tcp", c.Listen)
	if err != nil {
		j.emit("relay", err.Error(), nil)
		return errReported
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	go func() { _, _ = io.Copy(io.Discard, reader); cancel() }()
	go func() { <-ctx.Done(); listener.Close() }()
	go reportStats(ctx, core, j)
	j.emit("relay_ready", "local listener ready; remote readiness not yet verified", map[string]any{"listen": listener.Addr().String(), "core_version": coreVersion()})
	s := relay{username: c.Username, password: c.Password, journal: j,
		lookup: delegatedDNS(c.DNSAddress, addresses),
		dialTCP: func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
			return stack.DialContextTCPAddrPort(ctx, dst)
		},
		dialUDP: func(dst netip.AddrPort) (net.Conn, error) { return stack.DialUDPAddrPort(netip.AddrPort{}, dst) },
	}
	return s.serve(ctx, listener)
}

var errReported = fmt.Errorf("failure already recorded")

func reportStats(ctx context.Context, core *device.Device, j *journal) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			raw, err := core.IpcGet()
			if err != nil {
				j.emit("observer", err.Error(), nil)
				continue
			}
			// IpcGet includes private material. Export a strict numeric allowlist.
			var peers []map[string]uint64
			for _, line := range strings.Split(raw, "\n") {
				key, value, ok := strings.Cut(line, "=")
				if !ok {
					continue
				}
				if key == "public_key" {
					peers = append(peers, map[string]uint64{})
				}
				switch key {
				case "last_handshake_time_sec", "last_handshake_time_nsec", "tx_bytes", "rx_bytes":
					if len(peers) > 0 {
						if n, err := strconv.ParseUint(value, 10, 64); err == nil {
							peers[len(peers)-1][key] = n
						}
					}
				}
			}
			j.emit("stats", "", map[string]any{"peers": peers, "core_version": coreVersion()})
		}
	}
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println("zapret-amnezia", coreVersion())
		return
	}
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "configuration is accepted only through stdin")
		os.Exit(2)
	}
	if err := run(); err != nil {
		if err != errReported {
			newJournal(config{}).emit("process", err.Error(), nil)
		}
		os.Exit(1)
	}
}
