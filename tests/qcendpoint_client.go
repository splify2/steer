// SPDX-License-Identifier: GPL-3.0-only
// Lab client built against Hysteria's pinned apernet/quic-go; no runtime Go dependency.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	quic "github.com/apernet/quic-go"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

type capture struct {
	net.PacketConn
	mutex   sync.Mutex
	initial []byte
}

func zeroRTT(initial []byte) []byte {
	if len(initial) < 7 {
		panic("short Initial")
	}
	end := 6 + int(initial[5])
	if end >= len(initial) {
		panic("Initial DCID")
	}
	end += 1 + int(initial[end])
	if end > len(initial) {
		panic("Initial SCID")
	}
	// Syntactically complete 0-RTT packet with the same clear CID fields. No
	// ticket/early-data keys exist on this endpoint: ngtcp2 must discard it.
	packet := append([]byte{0xd0}, initial[1:end]...)
	packet = append(packet, 33)
	packet = append(packet, make([]byte, 33)...)
	return packet
}
func (c *capture) WriteTo(p []byte, a net.Addr) (int, error) {
	original := len(p)
	c.mutex.Lock()
	if len(c.initial) == 0 && len(p) >= 1200 && p[0]&128 != 0 {
		c.initial = append([]byte(nil), p...)
		p = append(append([]byte(nil), p...), zeroRTT(p)...)
	}
	c.mutex.Unlock()
	n, err := c.PacketConn.WriteTo(p, a)
	if err == nil && n == len(p) {
		return original, nil
	}
	return n, err
}
func config() *quic.Config {
	return &quic.Config{EnableDatagrams: true, HandshakeIdleTimeout: time.Second, MaxIdleTimeout: 5 * time.Second}
}
func tlsConfig() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"qcecho"}}
} // disposable fixture certificate only
func dial(address string, timeout time.Duration) *quic.Conn {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c, err := quic.DialAddr(ctx, address, tlsConfig(), config())
	if err != nil {
		panic(err)
	}
	return c
}
func echo(c *quic.Conn, tag byte) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stream, err := c.OpenStreamSync(ctx)
	if err != nil {
		panic(err)
	}
	payload := bytes.Repeat([]byte{tag, 0, 255, 128}, 4096)
	if _, err = stream.Write(payload); err != nil {
		panic(err)
	}
	if err = stream.Close(); err != nil {
		panic(err)
	}
	if err = stream.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		panic(err)
	}
	got, err := io.ReadAll(stream)
	if err != nil || !bytes.Equal(got, payload) {
		panic("stream echo mismatch")
	}
	if err = c.SendDatagram([]byte{tag, 0, 255}); err != nil {
		panic(err)
	}
	got, err = c.ReceiveDatagram(ctx)
	if err != nil || !bytes.Equal(got, []byte{tag, 0, 255}) {
		panic("datagram echo mismatch")
	}
}
func main() {
	if len(os.Args) != 2 && len(os.Args) != 3 {
		panic("usage: client 127.0.0.1:PORT")
	}
	address := os.Args[1]
	if len(os.Args) == 3 {
		if os.Args[2] != "release" {
			panic("unknown mode")
		}
		c := dial(address, 2*time.Second)
		echo(c, 7)
		fmt.Println("READY release")
		select {
		case <-c.Context().Done():
		case <-time.After(2 * time.Second):
			panic("child qc_free did not close connection")
		}
		fmt.Println("PASS endpoint-owned qc_free requests closure")
		return
	}
	peer, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		panic(err)
	}
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer socket.Close()
	captured := &capture{PacketConn: socket}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	one, err := quic.Dial(ctx, captured, peer, tlsConfig(), config())
	cancel()
	if err != nil {
		panic(err)
	}
	// Replaying a known Initial from a different peer must not admit a new child.
	foreign, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	captured.mutex.Lock()
	initial := append([]byte(nil), captured.initial...)
	captured.mutex.Unlock()
	if len(initial) == 0 {
		panic("no captured Initial")
	}
	if _, err = foreign.WriteTo(initial, peer); err != nil {
		panic(err)
	}
	foreign.Close()
	two := dial(address, 2*time.Second)
	var group sync.WaitGroup
	group.Add(2)
	go func() { defer group.Done(); echo(one, 1) }()
	go func() { defer group.Done(); echo(two, 2) }()
	group.Wait()
	ctx, cancel = context.WithTimeout(context.Background(), 400*time.Millisecond)
	extra, err := quic.DialAddr(ctx, address, tlsConfig(), config())
	cancel()
	if err == nil {
		extra.CloseWithError(0, "")
		panic("third client exceeded capacity")
	}
	echo(one, 3)
	echo(two, 4)
	fmt.Println("PASS coalesced Initial+0RTT is harmless; two concurrent connections streams/datagrams; third capacity rejection preserves both")
	one.CloseWithError(0, "")
	time.Sleep(100 * time.Millisecond)
	three := dial(address, 2*time.Second)
	echo(three, 5)
	echo(two, 6)
	fmt.Println("PASS closed child reaped and capacity reused; foreign-peer Initial rejected")
	time.Sleep(2200 * time.Millisecond)
	// No application-level close: server expiry must release idle children.
	fmt.Println("PASS idle interval completed")
}
