// Copy of transport/wireguard/family_race.go from the Android core patch
// 0021 (zapret-kvn/android core-patches), kept identical apart from the
// package name and raceAddresses: the Windows app resolves the two addresses.
package main

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// familyRaceBurstGap separates handshake attempts. WireGuard retries an
// unanswered initiation after REKEY_TIMEOUT (5 s); the junk packets and the
// initiation of one attempt are sent back to back, well inside this gap.
const familyRaceBurstGap = time.Second

// familyRace is the WireGuard counterpart of happy eyeballs for a server name
// with both an IPv6 and an IPv4 address.
//
// The first handshake attempt goes to both addresses. The server drops the
// second copy as a replay (same TAI64N timestamp), so exactly one copy is
// answered, and the family it came back on is kept for the session. Later
// attempts, if the first is not answered, alternate families starting with
// the preferred one: when one family loses only the replies (one-way
// filtering), a duplicate could keep reaching the server on that family
// first, and alternating still lets the other family answer.
//
// The engine keeps sending to the address it was configured with (roaming is
// off: main calls DisableSomeRoamingForBrokenMobileSemantics), so the bind
// sends to targets() instead of the engine's destination. Only the socket destination changes; the WireGuard
// protocol itself is untouched.
type familyRace struct {
	access    sync.Mutex
	order     func() (preferred, other netip.AddrPort)
	onLock    func(netip.AddrPort)
	now       func() time.Time
	preferred netip.AddrPort
	other     netip.AddrPort
	locked    netip.AddrPort
	attempt   int
	lastSend  time.Time
	// decided holds the one-element target list once the race is locked:
	// every later packet costs one atomic load, no lock and no allocation.
	decided atomic.Pointer[[]netip.AddrPort]
}

func newFamilyRace(order func() (netip.AddrPort, netip.AddrPort), onLock func(netip.AddrPort), now func() time.Time) *familyRace {
	if now == nil {
		now = time.Now
	}
	race := &familyRace{order: order, onLock: onLock, now: now}
	race.restart()
	return race
}

// restart begins a new race, for example when the bind is reopened after a
// network change. The order is asked again, so a remembered family leads.
func (r *familyRace) restart() {
	preferred, other := r.order()
	r.access.Lock()
	defer r.access.Unlock()
	r.preferred, r.other = unmapAddrPort(preferred), unmapAddrPort(other)
	r.locked = netip.AddrPort{}
	r.attempt = 0
	r.lastSend = time.Time{}
	r.decided.Store(nil)
}

// settled reports whether a family has been kept.
func (r *familyRace) settled() bool {
	return r.decided.Load() != nil
}

// targets returns the addresses the packets of one send go to.
func (r *familyRace) targets() []netip.AddrPort {
	if decided := r.decided.Load(); decided != nil {
		return *decided
	}
	r.access.Lock()
	defer r.access.Unlock()
	if r.locked.IsValid() {
		return []netip.AddrPort{r.locked}
	}
	now := r.now()
	if !r.lastSend.IsZero() && now.Sub(r.lastSend) > familyRaceBurstGap {
		r.attempt++
	}
	r.lastSend = now
	switch {
	case r.attempt == 0:
		return []netip.AddrPort{r.preferred, r.other}
	case r.attempt%2 == 1:
		return []netip.AddrPort{r.preferred}
	default:
		return []netip.AddrPort{r.other}
	}
}

// received notes a packet from source. The first packet from either server
// address locks its family; it reports whether this call locked the race.
func (r *familyRace) received(source netip.AddrPort) bool {
	if r.settled() {
		return false
	}
	source = unmapAddrPort(source)
	r.access.Lock()
	if r.locked.IsValid() || (source != r.preferred && source != r.other) {
		r.access.Unlock()
		return false
	}
	r.locked = source
	r.decided.Store(&[]netip.AddrPort{source})
	onLock := r.onLock
	r.access.Unlock()
	if onLock != nil {
		onLock(source)
	}
	return true
}

func unmapAddrPort(address netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(address.Addr().Unmap(), address.Port())
}
