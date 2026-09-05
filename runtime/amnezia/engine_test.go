package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

func enginePair(t *testing.T, extensions string) (*netstack.Net, *netstack.Net, *device.Device) {
	t.Helper()
	a, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	makeCore := func(ip string, key, public []byte, endpoint string) (*device.Device, *netstack.Net) {
		tun, stack, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(ip)}, nil, 1280)
		if err != nil {
			t.Fatal(err)
		}
		core := device.NewDevice(tun, conn.NewStdNetBind(), &device.Logger{Verbosef: func(string, ...any) {}, Errorf: func(string, ...any) {}})
		t.Cleanup(core.Close)
		ipc := "private_key=" + hex.EncodeToString(key) + "\n" + extensions + "public_key=" + hex.EncodeToString(public) + "\nallowed_ip=10.77.0.0/24\n"
		if endpoint != "" {
			ipc += "endpoint=" + endpoint + "\n"
		}
		if err := core.IpcSet(ipc); err != nil {
			t.Fatal(err)
		}
		if err := core.Up(); err != nil {
			t.Fatal(err)
		}
		return core, stack
	}
	serverCore, serverStack := makeCore("10.77.0.1", a.Bytes(), b.PublicKey().Bytes(), "")
	stats, err := serverCore.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	var port string
	for _, line := range strings.Split(stats, "\n") {
		if value, ok := strings.CutPrefix(line, "listen_port="); ok {
			port = value
		}
	}
	if n, err := strconv.Atoi(port); err != nil || n == 0 {
		t.Fatal("server did not bind UDP")
	}
	clientCore, clientStack := makeCore("10.77.0.2", b.Bytes(), a.PublicKey().Bytes(), net.JoinHostPort("127.0.0.1", port))
	return serverStack, clientStack, clientCore
}

// All outer packets remain on loopback. Inner traffic crosses the real official
// Noise/UDP engine and userspace netstack, never an OS VPN or a user's server.
func TestOfficialEngineEncryptedTCPUDP(t *testing.T) {
	for _, tc := range []struct{ name, extensions string }{
		{"wireguard", ""},
		{"awg2", "jc=2\njmin=4\njmax=8\ns1=27\ns2=21\ns3=27\ns4=15\nh1=100-110\nh2=200-210\nh3=300-310\nh4=400-410\ni1=<r 4>\n"},
		{"awg31", "jc=2\njmin=4\njmax=8\ns1=27\ns2=21\ns3=27\ns4=15\nh1=100-110\nh2=200-210\nh3=300-310\nh4=400-410\ni1=<r 4>\ni2=<r 4>\ni3=<r 4>\ni4=<r 4>\ni5=<r 4>\nheader_protection_key=" + strings.Repeat("ab", 32) + "\ncontent_padding_addition=0-124\nrandom_trailers=true\ndisable_cookies=true\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, client, core := enginePair(t, tc.extensions)
			tcpDst := netip.MustParseAddrPort("10.77.0.1:8443")
			tcp, err := server.ListenTCPAddrPort(tcpDst)
			if err != nil {
				t.Fatal(err)
			}
			defer tcp.Close()
			go func() {
				connection, err := tcp.Accept()
				if err == nil {
					defer connection.Close()
					io.Copy(connection, connection)
				}
			}()
			udpDst := netip.MustParseAddrPort("10.77.0.1:5353")
			udp, err := server.ListenUDPAddrPort(udpDst)
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
					t.Error("relay did not stop")
				}
			}()
			connection := login(t, l.Addr().String(), c)
			defer connection.Close()
			request(t, connection, 1, tcpDst)
			body := bytes.Repeat([]byte("encrypted"), 16384)
			writeDone := make(chan error, 1)
			go func() { _, err := connection.Write(body); writeDone <- err }()
			response := make([]byte, len(body))
			if _, err := io.ReadFull(connection, response); err != nil {
				t.Fatal("TCP", err)
			}
			if err := <-writeDone; err != nil || !bytes.Equal(body, response) {
				t.Fatal("TCP mismatch", err)
			}
			control := login(t, l.Addr().String(), c)
			defer control.Close()
			local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer local.Close()
			relayAddr := request(t, control, 3, local.LocalAddr().(*net.UDPAddr).AddrPort())
			for _, size := range []int{48, 1200, 20000} {
				packet := append([]byte{0, 0, 0}, addressBytes(udpDst)...)
				packet = append(packet, bytes.Repeat([]byte{77}, size)...)
				local.SetDeadline(time.Now().Add(3 * time.Second))
				local.WriteToUDPAddrPort(packet, relayAddr)
				buf := make([]byte, 65535)
				n, _, err := local.ReadFromUDPAddrPort(buf)
				if err != nil || !bytes.Equal(buf[:n], packet) {
					t.Fatal(fmt.Sprintf("UDP %d", size), err)
				}
			}
			stats, err := core.IpcGet()
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(stats, "last_handshake_time_sec=0\n") {
				t.Fatal("no authenticated handshake")
			}
		})
	}
}
