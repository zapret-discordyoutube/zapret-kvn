package main

import "testing"

// Entering through the WARP hop (owner decision 2026-11-25): the helper's UDP socket must stay on the default route,
// which is the TUN, so that the router sends this process into the hop. Binding it to the physical interface would
// bypass the hop and show the server's address to the provider.
func TestUnboundBindDoesNotBindToThePhysicalInterface(t *testing.T) {
	c := testConfig()
	c.Unbound = true
	bind := newProtectedBind(c, nil)
	protected := false
	bind.protect = func(*protectedBind) error { protected = true; return nil }
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}
	defer bind.Close()
	if protected {
		t.Fatal("an unbound socket was bound to the physical interface")
	}
}

func TestBoundBindStillBindsToThePhysicalInterface(t *testing.T) {
	bind := newProtectedBind(testConfig(), nil)
	protected := false
	bind.protect = func(*protectedBind) error { protected = true; return nil }
	if _, _, err := bind.Open(0); err != nil {
		t.Fatal(err)
	}
	defer bind.Close()
	if !protected {
		t.Fatal("the default mode must bind to the physical interface")
	}
}

func TestUnboundNeedsPeerAddressesNotNames(t *testing.T) {
	c := testConfig()
	c.Unbound = true
	c.Endpoint.Peers[0].Address = "server.example"
	if err := bootstrapPeers(&c); err == nil {
		t.Fatal("a peer name cannot be resolved without the physical interface")
	}
}
