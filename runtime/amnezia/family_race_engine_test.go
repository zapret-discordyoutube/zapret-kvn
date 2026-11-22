package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

// raceEnginePair starts a real official engine as the server on loopback and
// a client whose only peer has two addresses, wired exactly like main: the
// protected bind with the family race and roaming off.
func raceEnginePair(t *testing.T, preferred string) (server *netstack.Net, client *netstack.Net, locked func() []netip.AddrPort) {
	t.Helper()
	a, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	quiet := &device.Logger{Verbosef: func(string, ...any) {}, Errorf: func(string, ...any) {}}
	serverTun, serverStack, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.78.0.1")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	serverCore := device.NewDevice(serverTun, conn.NewStdNetBind(), quiet)
	t.Cleanup(serverCore.Close)
	if err := serverCore.IpcSet("private_key=" + hex.EncodeToString(a.Bytes()) + "\npublic_key=" +
		hex.EncodeToString(b.PublicKey().Bytes()) + "\nallowed_ip=10.78.0.0/24\n"); err != nil {
		t.Fatal(err)
	}
	if err := serverCore.Up(); err != nil {
		t.Fatal(err)
	}
	stats, err := serverCore.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	var port uint16
	for _, line := range strings.Split(stats, "\n") {
		if value, ok := strings.CutPrefix(line, "listen_port="); ok {
			n, _ := strconv.Atoi(value)
			port = uint16(n)
		}
	}
	if port == 0 {
		t.Fatal("server did not bind UDP")
	}

	c := config{Endpoint: endpointConfig{Peers: []peerConfig{{Address: preferred, RaceAddress: "127.0.0.1", Port: port}}}}
	var access sync.Mutex
	var kept []netip.AddrPort
	bind := newProtectedBind(c, func(address netip.AddrPort) {
		access.Lock()
		kept = append(kept, address)
		access.Unlock()
	})
	bind.protect = loopbackOnly
	clientTun, clientStack, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.78.0.2")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	clientCore := device.NewDevice(clientTun, bind, quiet)
	t.Cleanup(clientCore.Close)
	clientCore.DisableSomeRoamingForBrokenMobileSemantics()
	endpoint := netip.AddrPortFrom(netip.MustParseAddr(preferred), port)
	if err := clientCore.IpcSet("private_key=" + hex.EncodeToString(b.Bytes()) + "\npublic_key=" +
		hex.EncodeToString(a.PublicKey().Bytes()) + "\nendpoint=" + endpoint.String() + "\nallowed_ip=10.78.0.0/24\n"); err != nil {
		t.Fatal(err)
	}
	if err := clientCore.Up(); err != nil {
		t.Fatal(err)
	}
	return serverStack, clientStack, func() []netip.AddrPort {
		access.Lock()
		defer access.Unlock()
		return append([]netip.AddrPort(nil), kept...)
	}
}

// echoThroughTunnel opens TCP to the server through the tunnel and returns how
// long the first round trip took (it includes the WireGuard handshake).
func echoThroughTunnel(t *testing.T, server, client *netstack.Net) time.Duration {
	t.Helper()
	destination := netip.MustParseAddrPort("10.78.0.1:8443")
	listener, err := server.ListenTCPAddrPort(destination)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			defer connection.Close()
			io.Copy(connection, connection)
		}
	}()
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	connection, err := client.DialContextTCPAddrPort(ctx, destination)
	if err != nil {
		t.Fatal("tunnel TCP:", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := connection.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(connection, reply); err != nil || string(reply) != "ping" {
		t.Fatal("echo through the tunnel failed:", err, string(reply))
	}
	return time.Since(started)
}

func ipv6Loopback(t *testing.T) {
	t.Helper()
	probe, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	probe.Close()
}

// IPv6 is the preferred address but cannot be reached (documentation prefix,
// no route): the first handshake still completes over IPv4 at once, not after
// WireGuard's 5 s retry.
func TestEngineRaceFallsToIPv4WithoutWaitingWhenIPv6IsDead(t *testing.T) {
	server, client, locked := raceEnginePair(t, "2001:db8::1")
	took := echoThroughTunnel(t, server, client)
	if took > 3*time.Second {
		t.Fatalf("handshake waited for a retry: %v", took)
	}
	kept := locked()
	if len(kept) != 1 || !kept[0].Addr().Is4() {
		t.Fatalf("want IPv4 kept once, got %v", kept)
	}
}

// Both families reach the server: it answers one copy of the initiation (the
// other is a replay for it), the tunnel works and exactly one family is kept.
func TestEngineRaceWithBothFamiliesKeepsOneAndTheTunnelWorks(t *testing.T) {
	ipv6Loopback(t)
	server, client, locked := raceEnginePair(t, "::1")
	took := echoThroughTunnel(t, server, client)
	if took > 3*time.Second {
		t.Fatalf("handshake waited for a retry: %v", took)
	}
	if kept := locked(); len(kept) != 1 {
		t.Fatalf("want one kept family, got %v", kept)
	}
	// A second connection after the race is decided reuses the session.
	if connection, err := client.DialContextTCPAddrPort(context.Background(), netip.MustParseAddrPort("10.78.0.1:8443")); err == nil {
		connection.Close()
	}
	if kept := locked(); len(kept) != 1 {
		t.Fatalf("the race must be decided once, got %v", kept)
	}
}
