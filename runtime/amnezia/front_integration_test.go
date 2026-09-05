package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func freeTestPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func connectDomain(client net.Conn, host string, port uint16) error {
	packet := append([]byte{5, 1, 0, 3, byte(len(host))}, []byte(host)...)
	packet = binary.BigEndian.AppendUint16(packet, port)
	if _, err := client.Write(packet); err != nil {
		return err
	}
	var header [3]byte
	if _, err := io.ReadFull(client, header[:]); err != nil {
		return err
	}
	if header != [3]byte{5, 0, 0} {
		return fmt.Errorf("SOCKS reply %v", header)
	}
	_, err := readAddress(client)
	return err
}

// Required by the Windows bundle gate, optional for a standalone Go checkout.
// Uses the exact sing-box executable supplied by that gate, never an OS TUN or
// a public server. TCP, UDP, TLS and domain policy cross the real front/core.
func TestSingboxFrontOfficialTransportAndRouting(t *testing.T) {
	corePath := os.Getenv("AMNEZIA_TEST_SINGBOX")
	if corePath == "" {
		t.Skip("set AMNEZIA_TEST_SINGBOX to the locked sing-box binary")
	}
	server, client, _ := enginePair(t, "jc=2\njmin=4\njmax=8\ns1=27\ns2=21\ns3=27\ns4=15\nh1=100-110\nh2=200-210\nh3=300-310\nh4=400-410\nheader_protection_key="+strings.Repeat("ab", 32)+"\nrandom_trailers=true\ndisable_cookies=true\n")
	var proxyRequests, directRequests atomic.Int32
	proxyTLS := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxyRequests.Add(1); w.Write([]byte("through-peer")) }))
	proxyTLS.Listener.Close()
	var err error
	proxyTLS.Listener, err = server.ListenTCPAddrPort(netip.MustParseAddrPort("10.77.0.1:443"))
	if err != nil {
		t.Fatal(err)
	}
	proxyTLS.StartTLS()
	defer proxyTLS.Close()
	directTLS := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { directRequests.Add(1); w.Write([]byte("direct-only")) }))
	defer directTLS.Close()
	roots := x509.NewCertPool()
	roots.AddCert(proxyTLS.Certificate())
	roots.AddCert(directTLS.Certificate())

	udp, err := server.ListenUDPAddrPort(netip.MustParseAddrPort("10.77.0.1:5353"))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		data := make([]byte, 65535)
		for {
			n, addr, err := udp.ReadFrom(data)
			if err != nil {
				return
			}
			udp.WriteTo(data[:n], addr)
		}
	}()

	c := testConfig()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dnsPort, frontPort := freeTestPort(t), freeTestPort(t)
	s := relay{username: c.Username, password: c.Password, journal: newJournal(c),
		lookup: delegatedDNS(fmt.Sprintf("127.0.0.1:%d", dnsPort), []netip.Addr{netip.MustParseAddr("10.77.0.2")}),
		dialTCP: func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
			return client.DialContextTCPAddrPort(ctx, dst)
		},
		dialUDP: func(dst netip.AddrPort) (net.Conn, error) { return client.DialUDPAddrPort(netip.AddrPort{}, dst) },
	}
	relayDone := make(chan error, 1)
	go func() { relayDone <- s.serve(ctx, listener) }()
	defer func() {
		cancel()
		listener.Close()
		select {
		case <-relayDone:
		case <-time.After(3 * time.Second):
			t.Error("relay shutdown blocked")
		}
	}()

	configuration := map[string]any{
		"log": map[string]any{"level": "error"},
		"inbounds": []any{
			map[string]any{"type": "mixed", "tag": "front", "listen": "127.0.0.1", "listen_port": frontPort, "users": []any{map[string]any{"username": c.Username, "password": c.Password}}},
			map[string]any{"type": "direct", "tag": "private-dns", "listen": "127.0.0.1", "listen_port": dnsPort},
		},
		"outbounds": []any{
			map[string]any{"type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": listener.Addr().(*net.TCPAddr).Port, "version": "5", "username": c.Username, "password": c.Password},
			map[string]any{"type": "direct", "tag": "direct", "domain_resolver": "controlled-dns"},
		},
		"dns": map[string]any{"servers": []any{map[string]any{"type": "hosts", "tag": "controlled-dns", "predefined": map[string]any{"proxy.test": []string{"10.77.0.1"}, "direct.test": []string{"127.0.0.1"}, "blocked.test": []string{"10.77.0.1"}}}}, "final": "controlled-dns"},
		"route": map[string]any{"default_domain_resolver": "controlled-dns", "rules": []any{
			map[string]any{"inbound": []string{"private-dns"}, "action": "hijack-dns"},
			map[string]any{"domain": []string{"direct.test"}, "action": "route", "outbound": "direct"},
			map[string]any{"domain": []string{"blocked.test"}, "action": "reject"},
		}, "final": "proxy"},
	}
	configPath := filepath.Join(t.TempDir(), "front.json")
	encoded, _ := json.Marshal(configuration)
	if err := os.WriteFile(configPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "front.log")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	process := exec.Command(corePath, "run", "-c", configPath)
	process.Stdout, process.Stderr = log, log
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		process.Process.Kill()
		process.Wait()
		if t.Failed() {
			raw, _ := os.ReadFile(logPath)
			t.Log(string(raw))
		}
	}()
	frontAddress := fmt.Sprintf("127.0.0.1:%d", frontPort)
	deadline := time.Now().Add(8 * time.Second)
	for {
		probe, err := net.DialTimeout("tcp", frontAddress, 100*time.Millisecond)
		if err == nil {
			probe.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("sing-box did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, probe := range []struct {
		host string
		port uint16
		body string
	}{{"proxy.test", 443, "through-peer"}, {"direct.test", uint16(directTLS.Listener.Addr().(*net.TCPAddr).Port), "direct-only"}} {
		stream := login(t, frontAddress, c)
		if err := connectDomain(stream, probe.host, probe.port); err != nil {
			t.Fatal(probe.host, err)
		}
		secure := tls.Client(stream, &tls.Config{RootCAs: roots, ServerName: proxyTLS.Certificate().DNSNames[0], MinVersion: tls.VersionTLS12})
		if err := secure.Handshake(); err != nil {
			t.Fatal(probe.host, err)
		}
		fmt.Fprintf(secure, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", probe.host)
		body, err := io.ReadAll(secure)
		secure.Close()
		if err != nil || !bytes.Contains(body, []byte(probe.body)) {
			t.Fatalf("%s: %s (%v)", probe.host, body, err)
		}
	}
	blocked := login(t, frontAddress, c)
	if err := connectDomain(blocked, "blocked.test", 443); err == nil {
		t.Fatal("blocked destination admitted")
	}
	blocked.Close()
	if proxyRequests.Load() != 1 || directRequests.Load() != 1 {
		t.Fatalf("routing crossed paths: proxy=%d direct=%d", proxyRequests.Load(), directRequests.Load())
	}
	control := login(t, frontAddress, c)
	defer control.Close()
	local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	relayAddress := request(t, control, 3, local.LocalAddr().(*net.UDPAddr).AddrPort())
	if relayAddress.Addr().IsUnspecified() {
		relayAddress = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), relayAddress.Port())
	}
	// 65497 + the 10-byte SOCKS header fills an IPv4 UDP datagram. The
	// official inner stack must fragment/reassemble independently of its MTU.
	for _, size := range []int{1200, 8193, 16385, 20000, 65497} {
		packet := append([]byte{0, 0, 0}, addressBytes(netip.MustParseAddrPort("10.77.0.1:5353"))...)
		packet = append(packet, bytes.Repeat([]byte{87}, size)...)
		local.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := local.WriteToUDPAddrPort(packet, relayAddress); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 65535)
		n, _, err := local.ReadFromUDPAddrPort(buf)
		if err != nil || !bytes.Equal(packet, buf[:n]) {
			t.Fatalf("UDP across front/relay/core failed: received=%d expected=%d error=%v", n, len(packet), err)
		}
	}
}
