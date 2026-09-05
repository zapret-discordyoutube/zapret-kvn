package main

import (
	"encoding/binary"
	"fmt"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

func physicalSocketControl(index uint32) func(string, string, syscall.RawConn) error {
	return func(network, address string, raw syscall.RawConn) error {
		if index == 0 {
			return fmt.Errorf("physical interface index is required for bootstrap DNS")
		}
		var optionErr error
		err := raw.Control(func(fd uintptr) {
			if strings.HasSuffix(network, "6") {
				optionErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, 31, int(index))
			} else {
				var data [4]byte
				binary.BigEndian.PutUint32(data[:], index)
				optionErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, 31, int(binary.NativeEndian.Uint32(data[:])))
			}
		})
		if err != nil {
			return err
		}
		return optionErr
	}
}

func protectBind(bind *protectedBind) error {
	if bind.index == 0 {
		return fmt.Errorf("physical interface index is required on Windows")
	}
	if bind.allow4 {
		if err := bind.BindSocketToInterface4(bind.index, false); err != nil {
			return fmt.Errorf("protect IPv4 UDP socket: %w", err)
		}
	}
	if bind.allow6 {
		if err := bind.BindSocketToInterface6(bind.index, false); err != nil {
			return fmt.Errorf("protect IPv6 UDP socket: %w", err)
		}
	}
	return nil
}
