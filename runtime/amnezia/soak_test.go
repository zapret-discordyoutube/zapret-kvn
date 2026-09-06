package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

// Explicit long-running regression check: real encrypted traffic must survive
// both the relay's idle UDP flow expiry and the core's normal 120-second rekey.
// All packets stay on loopback; no credentials, public server or OS TUN needed.
func TestAWG2IdleAndRekey(t *testing.T) {
	if os.Getenv("AMNEZIA_TEST_SOAK") != "1" {
		t.Skip("set AMNEZIA_TEST_SOAK=1 for the 150-second transport check")
	}
	server, client, core := enginePair(t, "jc=2\njmin=4\njmax=8\ns1=27\ns2=21\ns3=27\ns4=15\nh1=100-110\nh2=200-210\nh3=300-310\nh4=400-410\ni1=<r 4>\n")
	tcpDst := netip.MustParseAddrPort("10.77.0.1:8443")
	tcp, err := server.ListenTCPAddrPort(tcpDst)
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	go func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	udpDst := netip.MustParseAddrPort("10.77.0.1:5353")
	udp, err := server.ListenUDPAddrPort(udpDst)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		b := make([]byte, 65535)
		for {
			n, a, err := udp.ReadFrom(b)
			if err != nil {
				return
			}
			udp.WriteTo(b[:n], a)
		}
	}()
	c := testConfig()
	s := relay{username: c.Username, password: c.Password, journal: newJournal(c),
		dialTCP: func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
			return client.DialContextTCPAddrPort(ctx, dst)
		},
		dialUDP: func(dst netip.AddrPort) (net.Conn, error) { return client.DialUDPAddrPort(netip.AddrPort{}, dst) },
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.serve(ctx, l) }()
	defer func() {
		cancel()
		l.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("relay shutdown blocked")
		}
	}()
	address := l.Addr().String()
	if corePath := os.Getenv("AMNEZIA_TEST_SINGBOX"); corePath != "" {
		frontPort := freeTestPort(t)
		address = startTestSingbox(t, corePath, map[string]any{
			"log":       map[string]any{"level": "error"},
			"inbounds":  []any{map[string]any{"type": "mixed", "listen": "127.0.0.1", "listen_port": frontPort, "users": []any{map[string]any{"username": c.Username, "password": c.Password}}}},
			"outbounds": []any{map[string]any{"type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": l.Addr().(*net.TCPAddr).Port, "version": "5", "username": c.Username, "password": c.Password}},
			"route":     map[string]any{"final": "proxy"},
		}, frontPort)
		t.Log("checking sing-box -> authenticated relay -> official AWG2")
	}
	stream := login(t, address, c)
	defer stream.Close()
	request(t, stream, 1, tcpDst)
	control := login(t, address, c)
	defer control.Close()
	local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	relayAddr := request(t, control, 3, local.LocalAddr().(*net.UDPAddr).AddrPort())
	if relayAddr.Addr().IsUnspecified() {
		relayAddr = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), relayAddr.Port())
	}
	handshake := func() string {
		raw, err := core.IpcGet()
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(raw, "\n") {
			if strings.HasPrefix(line, "last_handshake_time_sec=") {
				return line
			}
		}
		t.Fatal("missing handshake statistics")
		return ""
	}
	start := time.Now()
	var first string
	for _, second := range []int{0, 5, 10, 75, 80, 100, 125, 150} {
		if pause := time.Until(start.Add(time.Duration(second) * time.Second)); pause > 0 {
			time.Sleep(pause)
		}
		payload := bytes.Repeat([]byte(fmt.Sprintf("frame-%d", second)), 1024)
		stream.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := stream.Write(payload); err != nil {
			t.Fatal(second, "TCP write", err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(stream, got); err != nil || !bytes.Equal(got, payload) {
			t.Fatal(second, "TCP reply", err)
		}
		packet := append(append([]byte{0, 0, 0}, addressBytes(udpDst)...), payload...)
		local.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := local.WriteToUDPAddrPort(packet, relayAddr); err != nil {
			t.Fatal(second, "UDP write", err)
		}
		buffer := make([]byte, 65535)
		n, _, err := local.ReadFromUDPAddrPort(buffer)
		if err != nil || !bytes.Equal(buffer[:n], packet) {
			t.Fatal(second, "UDP reply", err)
		}
		fresh := login(t, address, c)
		request(t, fresh, 1, tcpDst)
		if _, err := fresh.Write([]byte("new-stream")); err != nil {
			t.Fatal(second, "new TCP write", err)
		}
		b := make([]byte, len("new-stream"))
		if _, err := io.ReadFull(fresh, b); err != nil || string(b) != "new-stream" {
			t.Fatal(second, "new TCP", err)
		}
		fresh.Close()
		current := handshake()
		if second == 0 {
			first = current
		}
		if second == 150 && current == first {
			t.Fatal("normal key refresh did not occur")
		}
		t.Logf("%ds: existing/new TCP and UDP passed; rekey=%v", second, current != first)
	}
}
