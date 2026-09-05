package network_test

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

func TestZapretCompletePacketWithHeadroom(t *testing.T) {
	for _, options := range []N.ReadWaitOptions{
		{}, {FrontHeadroom: 262}, {FrontHeadroom: 262, RearHeadroom: 32},
		{MTU: 1280, FrontHeadroom: 262, RearHeadroom: 32, ReadOverhead: 48},
		{IncreaseBuffer: true, FrontHeadroom: 262, RearHeadroom: 32},
	} {
		packet := options.NewPacketBuffer()
		payload := bytes.Repeat([]byte{0xa7}, 65527)
		n, err := packet.Write(payload)
		if err != nil || n != len(payload) || !bytes.Equal(packet.Bytes(), payload) {
			t.Fatalf("packet truncated: options=%+v n=%d error=%v", options, n, err)
		}
		options.PostReturn(packet)
		packet.ExtendHeader(options.FrontHeadroom)
		packet.Extend(options.RearHeadroom)
		packet.Release()
		options.Packet = true
		streamPacket := options.NewBuffer()
		if n, err := streamPacket.Write(payload); err != nil || n != len(payload) {
			t.Fatalf("connected datagram truncated: n=%d error=%v", n, err)
		}
		streamPacket.Release()
	}
}

func TestZapretPacketCopyPreservesLargePayload(t *testing.T) {
	payload := bytes.Repeat([]byte{0x51}, 65527)
	options := N.ReadWaitOptions{MTU: 1280, FrontHeadroom: 262, RearHeadroom: 32}
	packet := options.Copy(buf.As(payload))
	defer packet.Release()
	if !bytes.Equal(packet.Bytes(), payload) {
		t.Fatalf("headroom copy truncated: %d != %d", packet.Len(), len(payload))
	}
}

func TestZapretPacketReceivesLargeUDP(t *testing.T) {
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	sender, err := net.Dial("udp4", listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	for _, size := range []int{1200, 8193, 16385, 20000, 65497, 65507} {
		payload := bytes.Repeat([]byte{byte(size)}, size)
		if _, err := sender.Write(payload); err != nil {
			t.Fatal(err)
		}
		listener.SetReadDeadline(time.Now().Add(time.Second))
		packet := buf.NewPacket()
		_, _, err := packet.ReadPacketFrom(listener)
		if err != nil || !bytes.Equal(packet.Bytes(), payload) {
			t.Errorf("UDP truncated: got=%d want=%d error=%v", packet.Len(), size, err)
		}
		packet.Release()
	}
}
