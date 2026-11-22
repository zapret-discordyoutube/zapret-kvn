package main

import (
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

var (
	raceIPv6 = netip.MustParseAddrPort("[2001:db8::1]:51820")
	raceIPv4 = netip.MustParseAddrPort("192.0.2.1:51820")
)

type raceClock struct{ at time.Time }

func (c *raceClock) now() time.Time             { return c.at }
func (c *raceClock) advance(step time.Duration) { c.at = c.at.Add(step) }

func newTestRace(clock *raceClock, locked *[]netip.AddrPort) *familyRace {
	return newFamilyRace(
		func() (netip.AddrPort, netip.AddrPort) { return raceIPv6, raceIPv4 },
		func(address netip.AddrPort) { *locked = append(*locked, address) },
		clock.now,
	)
}

func TestFamilyRaceFirstAttemptGoesToBothFamilies(t *testing.T) {
	clock := &raceClock{at: time.Unix(1000, 0)}
	var locked []netip.AddrPort
	race := newTestRace(clock, &locked)
	// AWG junk packets and the initiation of one attempt: all to both.
	for range 3 {
		mustEqual(t, []netip.AddrPort{raceIPv6, raceIPv4}, race.targets(), "")
		clock.advance(10 * time.Millisecond)
	}
	mustEqual(t, 0, len(locked), "")
}

func TestFamilyRaceLocksTheFamilyThatAnswers(t *testing.T) {
	clock := &raceClock{at: time.Unix(1000, 0)}
	var locked []netip.AddrPort
	race := newTestRace(clock, &locked)
	race.targets()
	// A dual-stack socket reports IPv4 sources as IPv4-mapped IPv6.
	mapped := netip.AddrPortFrom(netip.AddrFrom16(raceIPv4.Addr().As16()), raceIPv4.Port())
	mustEqual(t, true, race.received(mapped), "")
	mustEqual(t, false, race.received(raceIPv6), "the race is decided once")
	mustEqual(t, []netip.AddrPort{raceIPv4}, locked, "")
	clock.advance(2 * time.Minute)
	mustEqual(t, []netip.AddrPort{raceIPv4}, race.targets(), "rekeys stay on the winner")
}

func TestFamilyRaceIgnoresOtherSources(t *testing.T) {
	clock := &raceClock{at: time.Unix(1000, 0)}
	var locked []netip.AddrPort
	race := newTestRace(clock, &locked)
	mustEqual(t, false, race.received(netip.MustParseAddrPort("198.51.100.7:51820")), "")
	mustEqual(t, false, race.received(netip.MustParseAddrPort("192.0.2.1:9999")), "")
	mustEqual(t, 0, len(locked), "")
	mustEqual(t, 2, len(race.targets()), "")
}

func TestFamilyRaceAlternatesWhenTheFirstAttemptIsNotAnswered(t *testing.T) {
	clock := &raceClock{at: time.Unix(1000, 0)}
	var locked []netip.AddrPort
	race := newTestRace(clock, &locked)
	mustEqual(t, 2, len(race.targets()), "")
	clock.advance(5 * time.Second)
	mustEqual(t, []netip.AddrPort{raceIPv6}, race.targets(), "")
	clock.advance(100 * time.Millisecond)
	mustEqual(t, []netip.AddrPort{raceIPv6}, race.targets(), "same attempt")
	clock.advance(5 * time.Second)
	mustEqual(t, []netip.AddrPort{raceIPv4}, race.targets(), "")
	clock.advance(5 * time.Second)
	mustEqual(t, []netip.AddrPort{raceIPv6}, race.targets(), "")
	mustEqual(t, true, race.received(raceIPv6), "")
	mustEqual(t, []netip.AddrPort{raceIPv6}, locked, "")
}

func TestFamilyRaceRestartAsksTheOrderAgain(t *testing.T) {
	clock := &raceClock{at: time.Unix(1000, 0)}
	preferIPv4 := false
	var locked []netip.AddrPort
	race := newFamilyRace(func() (netip.AddrPort, netip.AddrPort) {
		if preferIPv4 {
			return raceIPv4, raceIPv6
		}
		return raceIPv6, raceIPv4
	}, func(address netip.AddrPort) { locked = append(locked, address) }, clock.now)
	race.targets()
	mustEqual(t, true, race.received(raceIPv4), "")
	preferIPv4 = true
	race.restart()
	mustEqual(t, []netip.AddrPort{raceIPv4, raceIPv6}, race.targets(), "")
	clock.advance(5 * time.Second)
	mustEqual(t, []netip.AddrPort{raceIPv4}, race.targets(), "")
}

func mustEqual(t *testing.T, want, got any, note string) {
	t.Helper()
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("%s: want %v, got %v", note, want, got)
	}
}

// Two loopback "servers" on the same port, one per family, like one server
// name with an AAAA and an A record.
func listenServerPair(t *testing.T) (server6, server4 *net.UDPConn, port uint16) {
	t.Helper()
	for range 20 {
		c4, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Skipf("IPv4 loopback unavailable: %v", err)
		}
		p := c4.LocalAddr().(*net.UDPAddr).Port
		c6, err := net.ListenPacket("udp6", net.JoinHostPort("::1", strconv.Itoa(p)))
		if err != nil {
			c4.Close()
			continue
		}
		t.Cleanup(func() { c4.Close(); c6.Close() })
		return c6.(*net.UDPConn), c4.(*net.UDPConn), uint16(p)
	}
	t.Skip("no free port pair on IPv6 and IPv4 loopback")
	return nil, nil, 0
}

func readWithin(c *net.UDPConn, wait time.Duration) (string, netip.AddrPort, bool) {
	buffer := make([]byte, 128)
	_ = c.SetReadDeadline(time.Now().Add(wait))
	n, from, err := c.ReadFromUDPAddrPort(buffer)
	if err != nil {
		return "", netip.AddrPort{}, false
	}
	return string(buffer[:n]), from, true
}

func TestProtectedBindRacesBothFamiliesAndKeepsTheOneThatAnswers(t *testing.T) {
	server6, server4, port := listenServerPair(t)
	c := testConfig()
	c.Endpoint.Peers[0].Address, c.Endpoint.Peers[0].RaceAddress, c.Endpoint.Peers[0].Port = "::1", "127.0.0.1", port
	if _, _, err := c.validate(); err != nil {
		t.Fatal(err)
	}
	var locked []netip.AddrPort
	bind := newProtectedBind(c, func(address netip.AddrPort) { locked = append(locked, address) })
	receivers, _, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer bind.Close()
	// The engine addresses the configured IPv6 endpoint.
	endpoint, err := bind.ParseEndpoint(netip.AddrPortFrom(netip.MustParseAddr("::1"), port).String())
	if err != nil {
		t.Fatal(err)
	}
	if err := bind.Send([][]byte{[]byte("initiation")}, endpoint); err != nil {
		t.Fatal(err)
	}
	got6, _, ok6 := readWithin(server6, time.Second)
	got4, client4, ok4 := readWithin(server4, time.Second)
	mustEqual(t, true, ok6 && ok4, "first attempt reaches both families")
	mustEqual(t, "initiation", got6, "")
	mustEqual(t, "initiation", got4, "")

	// Only the IPv4 copy is answered.
	if _, err := server4.WriteToUDPAddrPort([]byte("response"), client4); err != nil {
		t.Fatal(err)
	}
	answered := make(chan struct{})
	for _, receive := range receivers {
		go func(receive conn.ReceiveFunc) {
			batch := bind.BatchSize()
			packets, sizes, endpoints := make([][]byte, batch), make([]int, batch), make([]conn.Endpoint, batch)
			for i := range packets {
				packets[i] = make([]byte, 128)
			}
			for {
				n, err := receive(packets, sizes, endpoints)
				if err != nil {
					return
				}
				for i := 0; i < n; i++ {
					if string(packets[i][:sizes[i]]) == "response" {
						close(answered)
						return
					}
				}
			}
		}(receive)
	}
	select {
	case <-answered:
	case <-time.After(2 * time.Second):
		t.Fatal("response not received")
	}
	mustEqual(t, []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)}, locked, "IPv4 kept")

	// The engine still names IPv6; data now goes over IPv4 only.
	if err := bind.Send([][]byte{[]byte("data")}, endpoint); err != nil {
		t.Fatal(err)
	}
	got4, _, ok4 = readWithin(server4, time.Second)
	mustEqual(t, true, ok4, "data over IPv4")
	mustEqual(t, "data", got4, "")
	_, _, ok6 = readWithin(server6, 200*time.Millisecond)
	mustEqual(t, false, ok6, "the losing family gets nothing after the lock")
}

func TestRaceAddressMustBeTheOtherFamilyOfTheOnlyPeer(t *testing.T) {
	for _, modify := range []func(*config){
		func(c *config) { c.Endpoint.Peers[0].RaceAddress = "127.0.0.2" },
		func(c *config) { c.Endpoint.Peers[0].RaceAddress = "::" },
		func(c *config) { c.Endpoint.Peers[0].RaceAddress = "vpn.example" },
		func(c *config) {
			c.Endpoint.Peers[0].RaceAddress = "::1"
			second := c.Endpoint.Peers[0]
			second.PublicKey = c.Endpoint.PrivateKey
			second.RaceAddress = ""
			c.Endpoint.Peers = append(c.Endpoint.Peers, second)
		},
	} {
		c := testConfig()
		modify(&c)
		if _, _, err := c.validate(); err == nil {
			t.Fatalf("accepted %+v", c.Endpoint.Peers)
		}
	}
	c := testConfig()
	c.Endpoint.Peers[0].RaceAddress = "::1"
	if _, _, err := c.validate(); err != nil {
		t.Fatal(err)
	}
	if bind := newProtectedBind(c, nil); !bind.raceReady || !bind.allow4 || !bind.allow6 {
		t.Fatal("race needs both families protected")
	}
	if bind := newProtectedBind(testConfig(), nil); bind.race != nil {
		t.Fatal("no race without race_address")
	}
}
