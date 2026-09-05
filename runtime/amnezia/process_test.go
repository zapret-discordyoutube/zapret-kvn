package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"
)

func TestTransportChildHelper(t *testing.T) {
	if os.Getenv("ZAPRET_AMNEZIA_TEST_CHILD") != "1" {
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func TestParentPipeEOFStopsCoreAndReleasesRelay(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 3; attempt++ {
		c := testConfig()
		c.Endpoint.Peers[0].Keepalive = json.RawMessage(`0`)
		if runtime.GOOS == "windows" {
			interfaces, err := net.Interfaces()
			if err != nil {
				t.Fatal(err)
			}
			for _, iface := range interfaces {
				if iface.Flags&net.FlagLoopback != 0 && iface.Flags&net.FlagUp != 0 {
					c.InterfaceIndex = uint32(iface.Index)
					break
				}
			}
			if c.InterfaceIndex == 0 {
				t.Fatal("test loopback interface unavailable")
			}
		}
		child := exec.Command(executable, "-test.run=^TestTransportChildHelper$")
		child.Env = append(os.Environ(), "ZAPRET_AMNEZIA_TEST_CHILD=1")
		stdin, err := child.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		stdout, err := child.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		child.Stderr = os.Stderr
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { child.Process.Kill() })
		ready := make(chan string, 1)
		go func() {
			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				var event map[string]any
				if json.Unmarshal(scanner.Bytes(), &event) == nil && event["stage"] == "relay_ready" {
					ready <- event["listen"].(string)
				}
			}
		}()
		if err := json.NewEncoder(stdin).Encode(c); err != nil {
			t.Fatal(err)
		}
		var address string
		select {
		case address = <-ready:
		case <-time.After(10 * time.Second):
			t.Fatal("child failed to initialize relay")
		}
		// Keep a client attached: losing the parent must also cancel active
		// clients, not just stop accepting new sockets.
		client, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		stdin.Close()
		done := make(chan error, 1)
		go func() { done <- child.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("parent EOF left a core/relay process alive")
		}
		client.Close()
		listener, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatal("old relay port still owned:", err)
		}
		listener.Close()
	}
}
