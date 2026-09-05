package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Only peer hostnames use physical-network bootstrap. SOCKS destinations
// exclusively use the separate sing-box DNS delegation, with no fallback here.
func bootstrapPeers(c *config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	dialer := &net.Dialer{Control: physicalSocketControl(c.InterfaceIndex)}
	for index := range c.Endpoint.Peers {
		peer := &c.Endpoint.Peers[index]
		if _, err := netip.ParseAddr(peer.Address); err == nil {
			continue
		}
		if len(c.BootstrapDNS) == 0 {
			return fmt.Errorf("peer[%d] bootstrap: physical network has no DNS server", index)
		}
		var last error
		resolved := false
		for _, raw := range c.BootstrapDNS {
			ip, err := netip.ParseAddr(raw)
			if err != nil || ip.IsUnspecified() || ip.IsMulticast() {
				return fmt.Errorf("invalid physical bootstrap DNS address")
			}
			for _, kind := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
				queryCtx, queryCancel := context.WithTimeout(ctx, 2*time.Second)
				ips, err := lookupDNS(queryCtx, netip.AddrPortFrom(ip, 53).String(), strings.TrimSuffix(peer.Address, ".")+".", kind, dialer)
				queryCancel()
				last = err
				for _, result := range ips {
					if result.IsUnspecified() || result.IsMulticast() {
						continue
					}
					peer.Address = result.Unmap().String()
					resolved = true
					break
				}
				if resolved || ctx.Err() != nil {
					break
				}
			}
			if resolved || ctx.Err() != nil {
				break
			}
		}
		if !resolved {
			return fmt.Errorf("peer[%d] bootstrap DNS failed: %v", index, last)
		}
	}
	return nil
}
