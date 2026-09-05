package main

import (
	"fmt"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"net/netip"
)

// Use the official portable UDP bind, not WinRing's packet buffer layout.
// Apply physical-interface binding on every Open, before any handshake send.
type protectedBind struct {
	*conn.StdNetBind
	index          uint32
	allow4, allow6 bool
}

func newProtectedBind(c config) *protectedBind {
	b := &protectedBind{StdNetBind: conn.NewStdNetBind().(*conn.StdNetBind), index: c.InterfaceIndex}
	for _, peer := range c.Endpoint.Peers {
		ip := netip.MustParseAddr(peer.Address)
		b.allow4 = b.allow4 || ip.Is4()
		b.allow6 = b.allow6 || ip.Is6()
	}
	return b
}

func (b *protectedBind) Send(packets [][]byte, endpoint conn.Endpoint) error {
	ip := endpoint.DstIP()
	if (ip.Is4() && !b.allow4) || (ip.Is6() && !b.allow6) || !ip.IsValid() {
		return fmt.Errorf("peer address family has no protected physical socket")
	}
	return b.StdNetBind.Send(packets, endpoint)
}

func (b *protectedBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.StdNetBind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	if err = protectBind(b); err != nil {
		b.StdNetBind.Close()
		return nil, 0, err
	}
	return fns, actual, nil
}
