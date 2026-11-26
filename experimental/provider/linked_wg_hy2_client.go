// Test-only, built in the pinned upstream Hysteria core module. This client
// never dials a non-loopback QUIC endpoint or requests a non-fixture target.
package main

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
)

func main() {
	if len(os.Args) != 4 || (os.Args[3] != "echo" && os.Args[3] != "reject") {
		panic("usage: oracle endpoint destination echo|reject")
	}
	server, err := net.ResolveUDPAddr("udp4", os.Args[1])
	host, _, targetErr := net.SplitHostPort(os.Args[2])
	if err != nil || !server.IP.IsLoopback() || targetErr != nil || host != "198.51.100.77" {
		panic("not a fixture address")
	}
	pem, err := os.ReadFile(os.Getenv("STEER_LAB_CA_FILE"))
	roots := x509.NewCertPool()
	if err != nil || !roots.AppendCertsFromPEM(pem) {
		panic("fixture CA unavailable")
	}
	c, info, err := client.NewClient(&client.Config{
		ServerAddr: server, Auth: os.Getenv("STEER_LAB_HY2_TOKEN"),
		TLSConfig: client.TLSConfig{ServerName: "localhost", RootCAs: roots},
	})
	if err != nil {
		panic(err)
	}
	if os.Getenv("STEER_TEST_LINKED_HY2") == "1" && info.UDPEnabled {
		panic("expected stream-only HY2")
	}
	defer c.Close()
	conn, err := c.TCP(os.Args[2])
	if os.Args[3] == "reject" {
		if err == nil {
			conn.Close()
			panic("expected TCP denial")
		}
		fmt.Println("PASS reject")
		return
	}
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	payload := []byte("independent HY2 client")
	if n, err := conn.Write(payload); n != len(payload) || err != nil {
		panic("TCP write failed")
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil || !bytes.Equal(reply, payload) {
		panic("TCP echo mismatch")
	}
	fmt.Println("PASS echo")
}
