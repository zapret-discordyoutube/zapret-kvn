//go:build !windows

package main

import (
	"fmt"
	"syscall"
)

func physicalSocketControl(index uint32) func(string, string, syscall.RawConn) error {
	return func(string, string, syscall.RawConn) error {
		if index != 0 {
			return fmt.Errorf("Windows interface binding requested on another platform")
		}
		return nil
	}
}

func protectBind(bind *protectedBind) error {
	if bind.index != 0 {
		return fmt.Errorf("Windows interface binding requested on another platform")
	}
	return nil // Host integration tests run without an OS TUN or route changes.
}
