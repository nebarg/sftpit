package sshfront

import (
	"errors"
	"net"
	"testing"
)

func TestANormallyClosedGateHandsOnNothing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	peer, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer peer.Close()
	server := <-accepted
	if server == nil {
		t.Fatal("Accept failed")
	}
	g := newGate(server)
	defer func() { _ = g.abort() }()

	if err := g.closeNormally(); err != nil {
		t.Fatalf("closeNormally: %v", err)
	}
	if _, err := peer.Write(make([]byte, 64*1024)); err != nil {
		t.Fatalf("peer Write: %v", err)
	}
	buf := make([]byte, 1024)
	for range 100 {
		if n, err := g.Read(buf); n != 0 || !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Read after a normal close = %d, %v; want 0, %v", n, err, net.ErrClosed)
		}
	}
}
