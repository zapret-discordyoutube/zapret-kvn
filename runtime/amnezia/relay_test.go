package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func startTestRelay(t *testing.T) (config, string) {
	t.Helper()
	c := testConfig()
	s := relay{username: c.Username, password: c.Password, journal: newJournal(c),
		dialTCP: func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", dst.String())
		},
		dialUDP: func(dst netip.AddrPort) (net.Conn, error) { return net.Dial("udp", dst.String()) },
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.serve(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		l.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("relay teardown blocked")
		}
	})
	return c, l.Addr().String()
}

func login(t *testing.T, address string, c config) net.Conn {
	t.Helper()
	client, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	client.SetDeadline(time.Now().Add(3 * time.Second))
	client.Write([]byte{5, 1, 2})
	var result [2]byte
	if _, err := io.ReadFull(client, result[:]); err != nil || result != [2]byte{5, 2} {
		t.Fatal("method", result, err)
	}
	credentials := append([]byte{1, byte(len(c.Username))}, []byte(c.Username)...)
	credentials = append(credentials, byte(len(c.Password)))
	credentials = append(credentials, []byte(c.Password)...)
	client.Write(credentials)
	if _, err := io.ReadFull(client, result[:]); err != nil || result != [2]byte{1, 0} {
		t.Fatal("authentication", result, err)
	}
	return client
}

func request(t *testing.T, client net.Conn, command byte, dst netip.AddrPort) netip.AddrPort {
	t.Helper()
	client.Write(append([]byte{5, command, 0}, addressBytes(dst)...))
	var response [3]byte
	if _, err := io.ReadFull(client, response[:]); err != nil || response != [3]byte{5, 0, 0} {
		t.Fatal("request", response, err)
	}
	addr, err := readAddress(client)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

func TestRelayTCPAndAuthentication(t *testing.T) {
	c, address := startTestRelay(t)
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		conn, err := echo.Accept()
		if err == nil {
			defer conn.Close()
			io.Copy(conn, conn)
		}
	}()
	client := login(t, address, c)
	request(t, client, 1, echo.Addr().(*net.TCPAddr).AddrPort())
	client.Write([]byte("transport-round-trip"))
	data := make([]byte, len("transport-round-trip"))
	if _, err := io.ReadFull(client, data); err != nil || string(data) != "transport-round-trip" {
		t.Fatal(string(data), err)
	}
	unauth, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer unauth.Close()
	unauth.SetDeadline(time.Now().Add(time.Second))
	unauth.Write([]byte{5, 1, 0})
	var response [2]byte
	if _, err := io.ReadFull(unauth, response[:]); err != nil || response[1] != 255 {
		t.Fatal("unauthenticated relay accepted", err)
	}
}

func TestRelayTCPHalfCloseKeepsDownload(t *testing.T) {
	c, address := startTestRelay(t)
	server, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	assertHalfCloseResponse(t, address, c, server, server.Addr().(*net.TCPAddr).AddrPort())
}

func assertHalfCloseResponse(t *testing.T, address string, c config, server net.Listener, dst netip.AddrPort) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		remote, err := server.Accept()
		if err != nil {
			done <- err
			return
		}
		defer remote.Close()
		remote.SetDeadline(time.Now().Add(3 * time.Second))
		body, err := io.ReadAll(remote)
		if err == nil {
			_, err = remote.Write(append([]byte("response:"), body...))
		}
		done <- err
	}()
	client := login(t, address, c)
	request(t, client, 1, dst)
	if _, err := client.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := client.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(client)
	if err != nil || string(response) != "response:request" {
		t.Fatalf("upload EOF discarded the response: %q (%v)", response, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRelayTCPCancellationUnblocksBothDirections(t *testing.T) {
	client, application := net.Pipe()
	remote, server := net.Pipe()
	defer application.Close()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- relayTCP(ctx, client, remote) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled relay retained a blocked stream")
	}
}

// More completed sessions than the relay's concurrency limit must not exhaust
// admission slots. A leak here would look like an alive core with no traffic.
func TestRelayCompletedConnectionsReleaseAdmission(t *testing.T) {
	c, address := startTestRelay(t)
	server, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() {
		for {
			remote, err := server.Accept()
			if err != nil {
				return
			}
			go func() { defer remote.Close(); io.Copy(remote, remote) }()
		}
	}()
	for i := 0; i < 384; i++ {
		client := login(t, address, c)
		request(t, client, 1, server.Addr().(*net.TCPAddr).AddrPort())
		if _, err := client.Write([]byte("round-trip")); err != nil {
			t.Fatal(i, err)
		}
		b := make([]byte, len("round-trip"))
		if _, err := io.ReadFull(client, b); err != nil || string(b) != "round-trip" {
			t.Fatal(i, "reply", err)
		}
		client.Close()
	}
}

func TestRelayUDPAssociationLifetimeAndSource(t *testing.T) {
	c, address := startTestRelay(t)
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			echo.WriteToUDP(buf[:n], addr)
		}
	}()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	client := login(t, address, c)
	relayAddr := request(t, client, 3, udp.LocalAddr().(*net.UDPAddr).AddrPort())
	packet := append([]byte{0, 0, 0}, addressBytes(echo.LocalAddr().(*net.UDPAddr).AddrPort())...)
	packet = append(packet, bytes.Repeat([]byte("a"), 20000)...)
	udp.SetDeadline(time.Now().Add(time.Second))
	udp.WriteToUDPAddrPort(packet, relayAddr)
	result := make([]byte, 65535)
	n, _, err := udp.ReadFromUDPAddrPort(result)
	if err != nil || !bytes.Equal(packet, result[:n]) {
		t.Fatal("UDP payload mismatch", n, err)
	}
	other, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	other.SetDeadline(time.Now().Add(100 * time.Millisecond))
	other.WriteToUDPAddrPort(packet, relayAddr)
	if _, _, err := other.ReadFromUDPAddrPort(result); err == nil {
		t.Fatal("foreign UDP source accepted")
	}
	client.Close()
	udp.SetDeadline(time.Now().Add(150 * time.Millisecond))
	udp.WriteToUDPAddrPort(packet, relayAddr)
	if _, _, err := udp.ReadFromUDPAddrPort(result); err == nil {
		t.Fatal("association survived control close")
	}
}
