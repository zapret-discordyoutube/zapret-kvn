package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type destination struct {
	address netip.AddrPort
	host    string
	port    uint16
}

func readDestination(r io.Reader) (destination, error) {
	var kind [1]byte
	if _, err := io.ReadFull(r, kind[:]); err != nil {
		return destination{}, err
	}
	if kind[0] != 3 {
		address, err := readAddress(io.MultiReader(strings.NewReader(string(kind[:])), r))
		return destination{address: address, port: address.Port()}, err
	}
	var length [1]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return destination{}, err
	}
	if length[0] == 0 {
		return destination{}, fmt.Errorf("empty SOCKS domain")
	}
	data := make([]byte, int(length[0])+2)
	if _, err := io.ReadFull(r, data); err != nil {
		return destination{}, err
	}
	host := string(data[:length[0]])
	for _, c := range host {
		if c <= 32 || c >= 127 {
			return destination{}, fmt.Errorf("SOCKS domain must be an ASCII DNS name")
		}
	}
	return destination{host: host, port: binary.BigEndian.Uint16(data[length[0]:])}, nil
}

func delegatedDNS(address string, locals []netip.Addr) func(context.Context, string) ([]netip.Addr, error) {
	v4, v6 := false, false
	for _, ip := range locals {
		v4 = v4 || ip.Is4()
		v6 = v6 || ip.Is6()
	}
	var types []dnsmessage.Type
	if v4 {
		types = append(types, dnsmessage.TypeA)
	}
	if v6 {
		types = append(types, dnsmessage.TypeAAAA)
	}
	return func(ctx context.Context, host string) ([]netip.Addr, error) {
		if address == "" {
			return nil, fmt.Errorf("sing-box DNS delegation is unavailable")
		}
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		// net.Resolver still consults the OS hosts file even with a custom Dial.
		// Exchange DNS directly with sing-box so its policy owns *every* name.
		type result struct {
			ips []netip.Addr
			err error
		}
		results := make(chan result, len(types))
		for _, kind := range types {
			go func() {
				ips, err := lookupDNS(ctx, address, strings.TrimSuffix(host, ".")+".", kind, &net.Dialer{})
				results <- result{ips, err}
			}()
		}
		var ips []netip.Addr
		var failures []error
		for range types {
			r := <-results
			ips = append(ips, r.ips...)
			if r.err != nil {
				failures = append(failures, r.err)
			}
		}
		if len(ips) != 0 {
			return ips, nil
		}
		if len(failures) != 0 {
			return nil, errors.Join(failures...)
		}
		return nil, fmt.Errorf("sing-box DNS returned no address for %s", host)
	}
}

func lookupDNS(ctx context.Context, server, host string, kind dnsmessage.Type, dialer *net.Dialer) ([]netip.Addr, error) {
	name, err := dnsmessage.NewName(host)
	if err != nil {
		return nil, err
	}
	for depth := 0; depth < 8; depth++ {
		var id [2]byte
		if _, err := rand.Read(id[:]); err != nil {
			return nil, err
		}
		question := dnsmessage.Question{Name: name, Type: kind, Class: dnsmessage.ClassINET}
		request := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: binary.BigEndian.Uint16(id[:]), RecursionDesired: true},
			Questions: []dnsmessage.Question{question},
		}
		response, err := exchangeDNS(ctx, server, request, dialer)
		if err != nil {
			return nil, err
		}
		if !response.Response || response.ID != request.ID || len(response.Questions) != 1 || response.Questions[0] != question || response.Truncated {
			return nil, fmt.Errorf("invalid sing-box DNS response")
		}
		if response.RCode != dnsmessage.RCodeSuccess {
			return nil, fmt.Errorf("sing-box DNS %s: %s", host, response.RCode)
		}
		// A recursive resolver normally includes the CNAME chain and its final
		// addresses. Accept only records belonging to that chain, never unrelated
		// answer/additional records. Ask sing-box again if the chain is incomplete.
		original := name
		for hop := 0; hop < 8; hop++ {
			var ips []netip.Addr
			var next *dnsmessage.CNAMEResource
			for _, answer := range response.Answers {
				if answer.Header.Class != dnsmessage.ClassINET || !strings.EqualFold(answer.Header.Name.String(), name.String()) {
					continue
				}
				switch body := answer.Body.(type) {
				case *dnsmessage.AResource:
					if kind == dnsmessage.TypeA {
						ips = append(ips, netip.AddrFrom4(body.A))
					}
				case *dnsmessage.AAAAResource:
					if kind == dnsmessage.TypeAAAA {
						ips = append(ips, netip.AddrFrom16(body.AAAA))
					}
				case *dnsmessage.CNAMEResource:
					next = body
				}
			}
			if len(ips) != 0 {
				return ips, nil
			}
			if next == nil {
				break
			}
			name = next.CNAME
		}
		if name == original {
			return nil, nil
		}
	}
	return nil, fmt.Errorf("sing-box DNS alias limit exceeded for %s", host)
}

func exchangeDNS(ctx context.Context, server string, request dnsmessage.Message, dialer *net.Dialer) (dnsmessage.Message, error) {
	var response dnsmessage.Message
	conn, err := dialer.DialContext(ctx, "tcp", server)
	if err != nil {
		return response, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	data, err := request.Pack()
	if err != nil {
		return response, err
	}
	packet := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(packet, uint16(len(data)))
	copy(packet[2:], data)
	if _, err = io.Copy(conn, strings.NewReader(string(packet))); err != nil {
		return response, err
	}
	var length [2]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return response, err
	}
	data = make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err := io.ReadFull(conn, data); err != nil {
		return response, err
	}
	err = response.Unpack(data)
	return response, err
}

func (s *relay) resolveDestination(ctx context.Context, d destination) ([]netip.AddrPort, error) {
	if d.address.IsValid() {
		return []netip.AddrPort{d.address}, nil
	}
	if s.lookup == nil {
		return nil, fmt.Errorf("sing-box DNS delegation is unavailable")
	}
	ips, err := s.lookup(ctx, d.host)
	if err != nil {
		return nil, fmt.Errorf("sing-box DNS lookup %s: %w", d.host, err)
	}
	var result []netip.AddrPort
	for _, ip := range ips {
		if !ip.IsUnspecified() && !ip.IsMulticast() {
			result = append(result, netip.AddrPortFrom(ip.Unmap(), d.port))
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("sing-box DNS returned no usable address for %s", d.host)
	}
	return result, nil
}
