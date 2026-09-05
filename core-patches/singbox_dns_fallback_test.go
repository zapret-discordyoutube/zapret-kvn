package fallback

import (
	"context"
	"errors"
	"testing"
	"time"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/logger"
)

type zapretDNSTestServer struct {
	adapter.DNSTransport
	tag   string
	code  int
	fail  bool
	calls *int
}

func (s *zapretDNSTestServer) Tag() string { return s.tag }
func (s *zapretDNSTestServer) Exchange(_ context.Context, _ *mDNS.Msg) (*mDNS.Msg, error) {
	*s.calls++
	if s.fail {
		return nil, errors.New("unreachable")
	}
	return &mDNS.Msg{MsgHdr: mDNS.MsgHdr{Rcode: s.code}}, nil
}

type zapretDNSTestLogger struct {
	logger.ContextLogger
	warnings int
}

func (l *zapretDNSTestLogger) InfoContext(context.Context, ...any) {}
func (l *zapretDNSTestLogger) WarnContext(context.Context, ...any) { l.warnings++ }

func TestZapretDNSFallbackRefusedUsesNextAndWarnsOnce(t *testing.T) {
	calls := [3]int{}
	servers := []adapter.DNSTransport{
		&zapretDNSTestServer{tag: "vpn-doh", code: mDNS.RcodeRefused, calls: &calls[0]},
		&zapretDNSTestServer{tag: "direct-doh", calls: &calls[1]},
		&zapretDNSTestServer{tag: "local-system-dns", calls: &calls[2]},
	}
	log := &zapretDNSTestLogger{}
	exchange := sequentialStrategy(servers, log, time.Second)
	for range 3 {
		response, err := exchange(context.Background(), &mDNS.Msg{})
		if err != nil || response.Rcode != mDNS.RcodeSuccess {
			t.Fatal(response, err)
		}
	}
	if calls != [3]int{3, 3, 0} || log.warnings != 1 {
		t.Fatal(calls, log.warnings)
	}
	servers[0].(*zapretDNSTestServer).code = mDNS.RcodeSuccess
	exchange(context.Background(), &mDNS.Msg{})
	servers[0].(*zapretDNSTestServer).code = mDNS.RcodeRefused
	exchange(context.Background(), &mDNS.Msg{})
	if log.warnings != 2 {
		t.Fatal("recovery must rearm fallback warning", log.warnings)
	}
}

func TestZapretDNSFallbackPlaintextIsLastAndNXDomainIsFinal(t *testing.T) {
	calls := [3]int{}
	servers := []adapter.DNSTransport{
		&zapretDNSTestServer{tag: "vpn-doh", fail: true, calls: &calls[0]},
		&zapretDNSTestServer{tag: "direct-doh", fail: true, calls: &calls[1]},
		&zapretDNSTestServer{tag: "local-system-dns", calls: &calls[2]},
	}
	exchange := sequentialStrategy(servers, &zapretDNSTestLogger{}, time.Second)
	if _, err := exchange(context.Background(), &mDNS.Msg{}); err != nil {
		t.Fatal(err)
	}
	if calls != [3]int{1, 1, 1} {
		t.Fatal(calls)
	}
	first := servers[0].(*zapretDNSTestServer)
	first.fail, first.code = false, mDNS.RcodeNameError
	if _, err := exchange(context.Background(), &mDNS.Msg{}); err != nil {
		t.Fatal(err)
	}
	if calls != [3]int{2, 1, 1} {
		t.Fatal("NXDOMAIN is not resolver failure", calls)
	}
}
