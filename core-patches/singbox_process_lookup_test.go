package process

// zapret-kvn regression tests for the cached Windows connection-owner lookup
// (core-patches/singbox-process-lookup-cache.patch). The cache logic has no
// build tag, so these tests also run on Linux build hosts.

import (
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type zapretTestRow struct {
	local netip.AddrPort
	pid   uint32
}

type zapretFakeClock struct {
	access sync.Mutex
	now    time.Time
}

func (c *zapretFakeClock) Now() time.Time {
	c.access.Lock()
	defer c.access.Unlock()
	return c.now
}

func (c *zapretFakeClock) Advance(delta time.Duration) {
	c.access.Lock()
	c.now = c.now.Add(delta)
	c.access.Unlock()
}

func zapretTCPCache(clock *zapretFakeClock, fetch func() ([]zapretTestRow, error)) *pidTableCache[zapretTestRow] {
	cache := newPidTableCache(fetch, func(row zapretTestRow, source netip.AddrPort) bool {
		return pidRowMatchesTCP(row.local, source)
	}, func(row zapretTestRow) uint32 { return row.pid })
	cache.now = clock.Now
	cache.sleep = func(time.Duration) {}
	return cache
}

var (
	zapretSourceA = netip.MustParseAddrPort("127.0.0.1:50001")
	zapretSourceB = netip.MustParseAddrPort("127.0.0.1:50002")
)

func TestZapretConcurrentMissesShareOneFetch(t *testing.T) {
	const waiters = 64
	clock := &zapretFakeClock{now: time.Unix(1000, 0)}
	var fetches atomic.Int32
	var entered atomic.Int32
	release := make(chan struct{})
	cache := zapretTCPCache(clock, func() ([]zapretTestRow, error) {
		fetches.Add(1)
		<-release
		return []zapretTestRow{{local: zapretSourceA, pid: 42}}, nil
	})
	var group sync.WaitGroup
	results := make(chan uint32, waiters)
	for range waiters {
		group.Add(1)
		go func() {
			defer group.Done()
			entered.Add(1)
			pid, found, err := cache.find(zapretSourceA)
			if err != nil || !found {
				t.Errorf("find: pid=%d found=%v err=%v", pid, found, err)
			}
			results <- pid
		}()
	}
	for entered.Load() < waiters {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	group.Wait()
	close(results)
	for pid := range results {
		if pid != 42 {
			t.Fatalf("pid = %d, want 42", pid)
		}
	}
	if got := fetches.Load(); got != 1 {
		t.Fatalf("fetches = %d, want exactly 1 shared fetch", got)
	}
}

func TestZapretStaleSnapshotRefreshesThenFinds(t *testing.T) {
	clock := &zapretFakeClock{now: time.Unix(1000, 0)}
	tables := [][]zapretTestRow{
		{{local: zapretSourceA, pid: 1}},
		{{local: zapretSourceA, pid: 1}, {local: zapretSourceB, pid: 2}},
	}
	var fetches int
	cache := zapretTCPCache(clock, func() ([]zapretTestRow, error) {
		rows := tables[min(fetches, len(tables)-1)]
		fetches++
		return rows, nil
	})
	if pid, found, err := cache.find(zapretSourceA); err != nil || !found || pid != 1 {
		t.Fatalf("first find: pid=%d found=%v err=%v", pid, found, err)
	}
	clock.Advance(100 * time.Millisecond)
	// Hit on a young snapshot: no fetch.
	if pid, found, _ := cache.find(zapretSourceA); !found || pid != 1 || fetches != 1 {
		t.Fatalf("cached hit: pid=%d found=%v fetches=%d", pid, found, fetches)
	}
	// Miss on a snapshot older than this lookup: one refresh, then found.
	if pid, found, err := cache.find(zapretSourceB); err != nil || !found || pid != 2 || fetches != 2 {
		t.Fatalf("refreshed find: pid=%d found=%v err=%v fetches=%d", pid, found, err, fetches)
	}
}

func TestZapretMissIsNotCached(t *testing.T) {
	clock := &zapretFakeClock{now: time.Unix(1000, 0)}
	var fetches int
	cache := zapretTCPCache(clock, func() ([]zapretTestRow, error) {
		fetches++
		return []zapretTestRow{{local: zapretSourceA, pid: 1}}, nil
	})
	if _, found, err := cache.find(zapretSourceB); err != nil || found {
		t.Fatalf("missing source found=%v err=%v", found, err)
	}
	// Same instant: the snapshot began no earlier than the lookup, the miss is final.
	if _, found, _ := cache.find(zapretSourceB); found || fetches != 1 {
		t.Fatalf("same-instant miss: found=%v fetches=%d", found, fetches)
	}
	clock.Advance(time.Millisecond)
	if _, found, _ := cache.find(zapretSourceB); found || fetches != 2 {
		t.Fatalf("later miss must refresh: found=%v fetches=%d", found, fetches)
	}
}

func TestZapretExpiredSnapshotIsNotUsedForHits(t *testing.T) {
	clock := &zapretFakeClock{now: time.Unix(1000, 0)}
	pids := []uint32{7, 9}
	var fetches int
	cache := zapretTCPCache(clock, func() ([]zapretTestRow, error) {
		pid := pids[min(fetches, len(pids)-1)]
		fetches++
		return []zapretTestRow{{local: zapretSourceA, pid: pid}}, nil
	})
	if pid, _, _ := cache.find(zapretSourceA); pid != 7 {
		t.Fatalf("pid = %d, want 7", pid)
	}
	clock.Advance(pidTableSnapshotTTL + time.Millisecond)
	// The port may have been reused by another process: an expired table
	// must not answer the hit.
	if pid, found, _ := cache.find(zapretSourceA); !found || pid != 9 || fetches != 2 {
		t.Fatalf("expired snapshot: pid=%d found=%v fetches=%d", pid, found, fetches)
	}
}

func TestZapretFetchErrorPropagatesAndIsRetried(t *testing.T) {
	clock := &zapretFakeClock{now: time.Unix(1000, 0)}
	failure := errors.New("GetExtendedTcpTable: access denied")
	var fetches int
	cache := zapretTCPCache(clock, func() ([]zapretTestRow, error) {
		fetches++
		if fetches == 1 {
			return nil, failure
		}
		return []zapretTestRow{{local: zapretSourceA, pid: 3}}, nil
	})
	if _, _, err := cache.find(zapretSourceA); !errors.Is(err, failure) {
		t.Fatalf("err = %v, want %v", err, failure)
	}
	if pid, found, err := cache.find(zapretSourceA); err != nil || !found || pid != 3 || fetches != 2 {
		t.Fatalf("retry: pid=%d found=%v err=%v fetches=%d", pid, found, err, fetches)
	}
}

func TestZapretFetchPanicReleasesWaiters(t *testing.T) {
	clock := &zapretFakeClock{now: time.Unix(1000, 0)}
	cache := zapretTCPCache(clock, func() ([]zapretTestRow, error) { panic("boom") })
	done := make(chan error, 1)
	go func() {
		_, _, err := cache.find(zapretSourceA)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("panicking fetch must surface an error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiter was not released after a panicking fetch")
	}
}

func TestZapretDuplicateRowsFirstMatchWins(t *testing.T) {
	clock := &zapretFakeClock{now: time.Unix(1000, 0)}
	cache := zapretTCPCache(clock, func() ([]zapretTestRow, error) {
		return []zapretTestRow{
			{local: zapretSourceB, pid: 5},
			{local: zapretSourceA, pid: 10},
			{local: zapretSourceA, pid: 20},
		}, nil
	})
	if pid, found, _ := cache.find(zapretSourceA); !found || pid != 10 {
		t.Fatalf("pid = %d, want the first matching row (10)", pid)
	}
}

func TestZapretUDPUnspecifiedRule(t *testing.T) {
	source4 := netip.MustParseAddrPort("192.168.1.5:5353")
	if !pidRowMatchesUDP(netip.MustParseAddrPort("0.0.0.0:5353"), source4, netip.IPv4Unspecified()) {
		t.Fatal("IPv4 wildcard row on the same port must match")
	}
	if pidRowMatchesUDP(netip.MustParseAddrPort("0.0.0.0:5354"), source4, netip.IPv4Unspecified()) {
		t.Fatal("IPv4 wildcard row on another port must not match")
	}
	if pidRowMatchesUDP(netip.MustParseAddrPort("10.0.0.1:5353"), source4, netip.IPv4Unspecified()) {
		t.Fatal("another concrete address must not match")
	}
	source6 := netip.MustParseAddrPort("[fd00::5]:443")
	if !pidRowMatchesUDP(netip.MustParseAddrPort("[::]:443"), source6, netip.IPv6Unspecified()) {
		t.Fatal("IPv6 wildcard row on the same port must match")
	}
	if pidRowMatchesTCP(netip.MustParseAddrPort("0.0.0.0:5353"), source4) {
		t.Fatal("TCP rows never use the wildcard rule")
	}
	// Table order decides between a wildcard and an exact row.
	clock := &zapretFakeClock{now: time.Unix(1000, 0)}
	cache := newPidTableCache(func() ([]zapretTestRow, error) {
		return []zapretTestRow{
			{local: netip.MustParseAddrPort("0.0.0.0:5353"), pid: 11},
			{local: source4, pid: 22},
		}, nil
	}, func(row zapretTestRow, source netip.AddrPort) bool {
		return pidRowMatchesUDP(row.local, source, netip.IPv4Unspecified())
	}, func(row zapretTestRow) uint32 { return row.pid })
	cache.now = clock.Now
	cache.sleep = func(time.Duration) {}
	if pid, found, _ := cache.find(source4); !found || pid != 11 {
		t.Fatalf("pid = %d, want the first matching (wildcard) row 11", pid)
	}
}

func TestZapretMinRefreshIntervalSpacesFetches(t *testing.T) {
	clock := &zapretFakeClock{now: time.Unix(1000, 0)}
	var slept []time.Duration
	var fetches int
	cache := zapretTCPCache(clock, func() ([]zapretTestRow, error) {
		fetches++
		return nil, nil
	})
	cache.minRefresh = 25 * time.Millisecond
	cache.sleep = func(duration time.Duration) {
		slept = append(slept, duration)
		clock.Advance(duration)
	}
	cache.find(zapretSourceA)
	clock.Advance(5 * time.Millisecond)
	cache.find(zapretSourceA)
	if fetches != 2 || len(slept) != 1 || slept[0] != 20*time.Millisecond {
		t.Fatalf("fetches=%d slept=%v, want one 20ms wait before the second fetch", fetches, slept)
	}
	if pidTableSnapshotTTL > 500*time.Millisecond {
		t.Fatalf("snapshot TTL %v exceeds the 500ms port-reuse bound", pidTableSnapshotTTL)
	}
}
