// SPDX-License-Identifier: GPL-3.0-only
// Independent loopback server fixture using upstream Hysteria core.
package main

import (
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
)

type auth string

func (a auth) Authenticate(_ net.Addr, password string, _ uint64) (bool, string) {
	return subtle.ConstantTimeCompare([]byte(a), []byte(password)) == 1, "lab"
}

type outbound string

func (o outbound) TCP(_ *server.RequestInfo, target string) (net.Conn, error) {
	if target == "target.test:"+string(o) || target == "127.0.0.1:"+string(o) {
		return net.DialTimeout("tcp4", "127.0.0.1:"+string(o), 2*time.Second)
	}
	return nil, errors.New("loopback fixture target not allowed")
}
func (outbound) UDP(*server.RequestInfo, string) (server.UDPConn, error) {
	return nil, errors.New("UDP disabled")
}
func (outbound) CheckUDP(*server.RequestInfo, string) error { return errors.New("UDP disabled") }

func main() {
	if len(os.Args) != 4 {
		panic("certificate key loopback-target-port required")
	}
	port, err := strconv.ParseUint(os.Args[3], 10, 16)
	if err != nil || port == 0 {
		panic("invalid port")
	}
	cert, err := tls.LoadX509KeyPair(os.Args[1], os.Args[2])
	if err != nil {
		panic(err)
	}
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	password := os.Getenv("STEER_LAB_HY2_TOKEN")
	if password == "" {
		panic("fixture password absent")
	}
	s, err := server.NewServer(&server.Config{
		TLSConfig:     server.TLSConfig{Certificates: []tls.Certificate{cert}},
		Conn:          conn,
		Authenticator: auth(password),
		Outbound:      outbound(os.Args[3]),
		DisableUDP:    true,
	})
	if err != nil {
		panic(err)
	}
	defer s.Close()
	fmt.Println(conn.LocalAddr().(*net.UDPAddr).Port)
	panic(s.Serve())
}
