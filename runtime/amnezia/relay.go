package main

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

type relay struct {
	username, password string
	journal            *journal
	dialTCP            func(context.Context, netip.AddrPort) (net.Conn, error)
	dialUDP            func(netip.AddrPort) (net.Conn, error)
	lookup             func(context.Context, string) ([]netip.Addr, error)
}

func (s *relay) serve(ctx context.Context, listener net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer listener.Close()
	var wg sync.WaitGroup
	defer wg.Wait()
	// Cancel clients before waiting, including on an unexpected Accept error.
	defer cancel()
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	limit := make(chan struct{}, 256)
	for {
		client, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case limit <- struct{}{}:
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-limit }()
				defer client.Close()
				stop := context.AfterFunc(ctx, func() { client.Close() })
				defer stop()
				if err := s.handle(ctx, client); err != nil && ctx.Err() == nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
					s.journal.emit("relay_connection", err.Error(), nil)
				}
			}()
		default:
			client.Close()
		}
	}
}

func (s *relay) authenticate(c net.Conn) error {
	var header [2]byte
	if _, err := io.ReadFull(c, header[:]); err != nil {
		return err
	}
	if header[0] != 5 || header[1] == 0 {
		return fmt.Errorf("invalid SOCKS greeting")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}
	found := false
	for _, method := range methods {
		found = found || method == 2
	}
	if !found {
		_, _ = c.Write([]byte{5, 255})
		return fmt.Errorf("SOCKS username/password authentication required")
	}
	if _, err := c.Write([]byte{5, 2}); err != nil {
		return err
	}
	if _, err := io.ReadFull(c, header[:]); err != nil {
		return err
	}
	if header[0] != 1 || header[1] == 0 {
		return fmt.Errorf("invalid SOCKS authentication")
	}
	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(c, username); err != nil {
		return err
	}
	var length [1]byte
	if _, err := io.ReadFull(c, length[:]); err != nil {
		return err
	}
	password := make([]byte, int(length[0]))
	if _, err := io.ReadFull(c, password); err != nil {
		return err
	}
	ok := subtle.ConstantTimeCompare(username, []byte(s.username)) & subtle.ConstantTimeCompare(password, []byte(s.password))
	status := byte(1)
	if ok == 1 {
		status = 0
	}
	if _, err := c.Write([]byte{1, status}); err != nil {
		return err
	}
	if status != 0 {
		return fmt.Errorf("SOCKS authentication rejected")
	}
	return nil
}

// Domain names are deliberately rejected: the front owns DNS. This avoids a
// second resolver and a hidden direct lookup path inside the protocol backend.
func readAddress(r io.Reader) (netip.AddrPort, error) {
	var kind [1]byte
	if _, err := io.ReadFull(r, kind[:]); err != nil {
		return netip.AddrPort{}, err
	}
	n := 0
	switch kind[0] {
	case 1:
		n = 4
	case 4:
		n = 16
	default:
		return netip.AddrPort{}, fmt.Errorf("SOCKS destination must be a resolved IP")
	}
	data := make([]byte, n+2)
	if _, err := io.ReadFull(r, data); err != nil {
		return netip.AddrPort{}, err
	}
	ip, _ := netip.AddrFromSlice(data[:n])
	return netip.AddrPortFrom(ip.Unmap(), binary.BigEndian.Uint16(data[n:])), nil
}

func addressBytes(address netip.AddrPort) []byte {
	kind := byte(4)
	if address.Addr().Is4() {
		kind = 1
	}
	data := append([]byte{kind}, address.Addr().AsSlice()...)
	return binary.BigEndian.AppendUint16(data, address.Port())
}

func reply(c net.Conn, status byte, address netip.AddrPort) error {
	_, err := c.Write(append([]byte{5, status, 0}, addressBytes(address)...))
	return err
}

var emptyAddress = netip.MustParseAddrPort("0.0.0.0:0")

func (s *relay) handle(ctx context.Context, client net.Conn) error {
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	if err := s.authenticate(client); err != nil {
		return err
	}
	var request [3]byte
	if _, err := io.ReadFull(client, request[:]); err != nil {
		return err
	}
	if request[0] != 5 || request[2] != 0 {
		return fmt.Errorf("invalid SOCKS request")
	}
	target, err := readDestination(client)
	if err != nil {
		_ = reply(client, 8, emptyAddress)
		return err
	}
	switch request[1] {
	case 1:
		addresses, err := s.resolveDestination(ctx, target)
		if err != nil {
			_ = reply(client, 4, emptyAddress)
			return err
		}
		dst := addresses[0]
		if dst.Port() == 0 || dst.Addr().IsUnspecified() || dst.Addr().IsMulticast() {
			_ = reply(client, 8, emptyAddress)
			return fmt.Errorf("invalid TCP destination")
		}
		dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		var remote net.Conn
		for _, address := range addresses {
			remote, err = s.dialTCP(dialCtx, address)
			if err == nil {
				break
			}
		}
		if err != nil {
			_ = reply(client, 5, emptyAddress)
			return fmt.Errorf("TCP %s: %w", dst, err)
		}
		defer remote.Close()
		if err := reply(client, 0, emptyAddress); err != nil {
			return err
		}
		_ = client.SetDeadline(time.Time{})
		done := make(chan struct{})
		go func() { _, _ = io.Copy(remote, client); remote.Close(); close(done) }()
		_, err = io.Copy(client, remote)
		client.Close()
		remote.Close()
		<-done
		return err
	case 3:
		_ = client.SetDeadline(time.Time{})
		return s.associate(ctx, client)
	default:
		_ = reply(client, 7, emptyAddress)
		return fmt.Errorf("unsupported SOCKS command %d", request[1])
	}
}

func (s *relay) associate(ctx context.Context, control net.Conn) error {
	peer := control.RemoteAddr().(*net.TCPAddr).AddrPort()
	if !peer.Addr().IsLoopback() {
		_ = reply(control, 2, emptyAddress)
		return fmt.Errorf("UDP association source must match authenticated loopback client")
	}
	local := control.LocalAddr().(*net.TCPAddr).AddrPort().Addr()
	udp, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(local, 0)))
	if err != nil {
		return err
	}
	defer udp.Close()
	if err := reply(control, 0, udp.LocalAddr().(*net.UDPAddr).AddrPort()); err != nil {
		return err
	}
	// An association cannot outlive the authenticated TCP connection.
	done := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, control); udp.Close(); close(done) }()
	defer func() { control.Close(); <-done }()
	var mu sync.Mutex
	flows := map[netip.AddrPort]net.Conn{}
	var readers sync.WaitGroup
	defer func() {
		mu.Lock()
		for _, flow := range flows {
			flow.Close()
		}
		mu.Unlock()
		readers.Wait()
	}()
	// sing-box sends the destination (possibly a domain), not the client's
	// source, in UDP ASSOCIATE. Ownership comes from the authenticated TCP
	// peer and the first valid UDP datagram; never trust request DST as source.
	var sourcePort uint16
	buffer := make([]byte, 65535)
	for {
		_ = udp.SetReadDeadline(time.Now().Add(2 * time.Minute))
		n, source, err := udp.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return err
		}
		if source.Addr().Unmap() != peer.Addr().Unmap() || (sourcePort != 0 && source.Port() != sourcePort) {
			continue
		}
		if n < 4 || buffer[0] != 0 || buffer[1] != 0 || buffer[2] != 0 {
			continue
		} // No SOCKS fragmentation.
		r := &sliceReader{data: buffer[3:n]}
		target, err := readDestination(r)
		if err != nil {
			continue
		}
		addresses, err := s.resolveDestination(ctx, target)
		if err != nil {
			s.journal.emit("destination_dns", err.Error(), nil)
			continue
		}
		destination := addresses[0]
		if err != nil || destination.Port() == 0 || destination.Addr().IsUnspecified() || destination.Addr().IsMulticast() {
			continue
		}
		if sourcePort == 0 {
			sourcePort = source.Port()
		}
		mu.Lock()
		flow := flows[destination]
		if flow == nil && len(flows) < 64 {
			flow, err = s.dialUDP(destination)
			if err == nil {
				flows[destination] = flow
				readers.Add(1)
				go func(flow net.Conn, destination, client netip.AddrPort) {
					defer readers.Done()
					defer flow.Close()
					defer func() {
						mu.Lock()
						if flows[destination] == flow {
							delete(flows, destination)
						}
						mu.Unlock()
					}()
					packet := make([]byte, 65535)
					for {
						_ = flow.SetReadDeadline(time.Now().Add(time.Minute))
						n, err := flow.Read(packet)
						if err != nil {
							return
						}
						response := append([]byte{0, 0, 0}, addressBytes(destination)...)
						response = append(response, packet[:n]...)
						if _, err := udp.WriteToUDPAddrPort(response, client); err != nil {
							return
						}
					}
				}(flow, destination, source)
			}
		}
		mu.Unlock()
		if err != nil {
			s.journal.emit("udp", fmt.Sprintf("UDP %s: %v", destination, err), nil)
			continue
		}
		if flow == nil {
			continue
		}
		_ = flow.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := flow.Write(r.data); err != nil {
			s.journal.emit("udp", fmt.Sprintf("UDP %s: %v", destination, err), nil)
			flow.Close()
		}
	}
}

type sliceReader struct{ data []byte }

func (r *sliceReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}
