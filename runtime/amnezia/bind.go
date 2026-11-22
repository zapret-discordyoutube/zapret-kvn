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
	// race is set when the only peer has addresses of both families.
	race      *familyRace
	raceEnds  map[netip.AddrPort]conn.Endpoint
	raceReady bool
}

func newProtectedBind(c config, onLock func(netip.AddrPort)) *protectedBind {
	b := &protectedBind{StdNetBind: conn.NewStdNetBind().(*conn.StdNetBind), index: c.InterfaceIndex}
	for _, peer := range c.Endpoint.Peers {
		ip := netip.MustParseAddr(peer.Address).Unmap()
		b.allow4 = b.allow4 || ip.Is4()
		b.allow6 = b.allow6 || ip.Is6()
	}
	if len(c.Endpoint.Peers) == 1 && c.Endpoint.Peers[0].RaceAddress != "" {
		peer := c.Endpoint.Peers[0]
		preferred := netip.AddrPortFrom(netip.MustParseAddr(peer.Address).Unmap(), peer.Port)
		other := netip.AddrPortFrom(netip.MustParseAddr(peer.RaceAddress).Unmap(), peer.Port)
		b.allow4, b.allow6 = true, true
		b.race = newFamilyRace(func() (netip.AddrPort, netip.AddrPort) { return preferred, other }, onLock, nil)
		b.raceEnds = map[netip.AddrPort]conn.Endpoint{}
		for _, address := range []netip.AddrPort{preferred, other} {
			endpoint, err := b.StdNetBind.ParseEndpoint(address.String())
			if err == nil {
				b.raceEnds[address] = endpoint
			}
		}
		b.raceReady = len(b.raceEnds) == 2
	}
	return b
}

func (b *protectedBind) Send(packets [][]byte, endpoint conn.Endpoint) error {
	ip := endpoint.DstIP()
	if (ip.Is4() && !b.allow4) || (ip.Is6() && !b.allow6) || !ip.IsValid() {
		return fmt.Errorf("peer address family has no protected physical socket")
	}
	if !b.raceReady {
		return b.StdNetBind.Send(packets, endpoint)
	}
	// One unreachable family must not fail the send while the other delivers.
	var err error
	delivered := false
	for _, target := range b.race.targets() {
		if sendErr := b.StdNetBind.Send(packets, b.raceEnds[target]); sendErr != nil {
			err = sendErr
		} else {
			delivered = true
		}
	}
	if !delivered {
		return err
	}
	return nil
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
	if b.raceReady {
		b.race.restart()
		for index, receive := range fns {
			fns[index] = b.watchRace(receive)
		}
	}
	return fns, actual, nil
}

// watchRace reports the sources of received packets to the race until it is
// decided; after that a packet costs one atomic load.
func (b *protectedBind) watchRace(receive conn.ReceiveFunc) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		n, err := receive(packets, sizes, endpoints)
		for index := 0; index < n && !b.race.settled(); index++ {
			if endpoint, ok := endpoints[index].(*conn.StdNetEndpoint); ok {
				b.race.received(endpoint.AddrPort)
			}
		}
		return n, err
	}
}
