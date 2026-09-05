package main

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

func TestSharedGoldenNativeJSONToOfficialUAPI(t *testing.T) {
	raw, err := os.ReadFile("testdata/wg_awg_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Vectors []struct {
			ID       string         `json:"id"`
			Valid    bool           `json:"valid"`
			Endpoint endpointConfig `json:"endpoint"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, vector := range fixture.Vectors {
		if !vector.Valid {
			continue
		}
		t.Run(vector.ID, func(t *testing.T) {
			c := testConfig()
			c.Endpoint = vector.Endpoint
			addresses, ipc, err := c.validate()
			if err != nil {
				t.Fatal(err)
			}
			tun, _, err := netstack.CreateNetTUN(addresses, nil, c.Endpoint.MTU)
			if err != nil {
				t.Fatal(err)
			}
			core := device.NewDevice(tun, conn.NewStdNetBind(), &device.Logger{Verbosef: func(string, ...any) {}, Errorf: func(string, ...any) {}})
			defer core.Close()
			if err := core.IpcSet(ipc); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNativeRangesCannotOverflowOrChangeOrder(t *testing.T) {
	for _, raw := range []string{`"0-4294967296"`, `4294967296`, `"20-10"`, `"+1"`, `{"from":1}`, `{"from":2,"to":1}`, `{"from":0,"to":4294967296}`, `{"from":0,"to":1,"ignored":true}`} {
		if _, err := uint32Range(json.RawMessage(raw)); err == nil {
			t.Fatalf("invalid range accepted: %s", raw)
		}
	}
	for raw, want := range map[string]string{`0`: "0", `"4294967295"`: "4294967295", `{"from":0,"to":124}`: "0-124", `"20-30"`: "20-30"} {
		got, err := uint32Range(json.RawMessage(raw))
		if err != nil || got != want {
			t.Fatalf("range %s: got %s (%v)", raw, got, err)
		}
	}
}
