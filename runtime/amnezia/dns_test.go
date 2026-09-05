package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestDNSDelegatesOnlyToConfiguredSingboxListener(t *testing.T) {
	server, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	questions := make(chan dnsmessage.Question, 8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			client, err := server.Accept()
			if err != nil {
				return
			}
			client.SetDeadline(time.Now().Add(time.Second))
			var length [2]byte
			if _, err := io.ReadFull(client, length[:]); err != nil {
				client.Close()
				return
			}
			data := make([]byte, binary.BigEndian.Uint16(length[:]))
			if _, err := io.ReadFull(client, data); err != nil {
				client.Close()
				return
			}
			var request dnsmessage.Message
			if err := request.Unpack(data); err != nil {
				client.Close()
				return
			}
			response := dnsmessage.Message{
				Header:    dnsmessage.Header{ID: request.ID, Response: true, RecursionAvailable: true},
				Questions: request.Questions,
			}
			for _, q := range request.Questions {
				questions <- q
				if q.Type == dnsmessage.TypeA {
					response.Answers = append(response.Answers, dnsmessage.Resource{
						Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 1},
						Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, 42}},
					})
				}
			}
			encoded, err := response.Pack()
			if err != nil {
				client.Close()
				return
			}
			binary.BigEndian.PutUint16(length[:], uint16(len(encoded)))
			client.Write(append(length[:], encoded...))
			client.Close()
		}
	}()
	lookup := delegatedDNS(server.Addr().String(), []netip.Addr{netip.MustParseAddr("10.0.0.2")})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, host := range []string{"only-in-singbox.invalid", "localhost"} {
		ips, err := lookup(ctx, host)
		if err != nil {
			t.Fatal(err)
		}
		if len(ips) != 1 || ips[0] != netip.MustParseAddr("192.0.2.42") {
			t.Fatalf("%s bypassed sing-box DNS: %v", host, ips)
		}
	}
	server.Close()
	<-done
	close(questions)
	count := 0
	for q := range questions {
		count++
		if (q.Name.String() != "only-in-singbox.invalid." && q.Name.String() != "localhost.") || q.Type != dnsmessage.TypeA {
			t.Fatalf("unexpected DNS query: %v", q)
		}
	}
	if count != 2 {
		t.Fatalf("expected both names at the private listener, got %d", count)
	}
}

func TestMissingDelegationDoesNotUseSystemDNS(t *testing.T) {
	lookup := delegatedDNS("", []netip.Addr{netip.MustParseAddr("10.0.0.2")})
	if ips, err := lookup(context.Background(), "localhost"); err == nil || len(ips) != 0 {
		t.Fatalf("missing sing-box DNS accepted: %v %v", ips, err)
	}
}

func TestRelayListenerFailureCancelsActiveClients(t *testing.T) {
	c := testConfig()
	s := relay{username: c.Username, password: c.Password, journal: newJournal(c)}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() { done <- s.serve(context.Background(), listener) }()
	client := login(t, listener.Addr().String(), c)
	defer client.Close()
	listener.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("unexpected listener failure was hidden")
		}
	case <-time.After(time.Second):
		t.Fatal("listener failure left active clients running")
	}
}
