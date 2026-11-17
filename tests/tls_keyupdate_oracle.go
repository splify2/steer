// Independent Go TLS handshake + RFC8446 KeyUpdate oracle, never logs traffic keys.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

type capturedConn struct {
	net.Conn
	wire []byte
}

func (c *capturedConn) Write(p []byte) (int, error) {
	n, e := c.Conn.Write(p)
	if len(c.wire)+n > 262144 {
		return n, errors.New("bounded capture")
	}
	c.wire = append(c.wire, p[:n]...)
	return n, e
}

type epoch struct {
	secret []byte
	aead   cipher.AEAD
	iv     []byte
	seq    uint64
	hf     func() hash.Hash
	keylen int
}

func expand(secret []byte, hf func() hash.Hash, label string, n int) []byte {
	info := []byte{byte(n >> 8), byte(n), byte(len(label) + 6)}
	info = append(info, []byte("tls13 "+label)...)
	info = append(info, 0, 1)
	mac := hmac.New(hf, secret)
	mac.Write(info)
	return mac.Sum(nil)[:n]
}
func (e *epoch) setup() error {
	key := expand(e.secret, e.hf, "key", e.keylen)
	e.iv = expand(e.secret, e.hf, "iv", 12)
	b, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	e.aead, err = cipher.NewGCM(b)
	e.seq = 0
	return err
}
func (e *epoch) nonce() []byte {
	n := append([]byte(nil), e.iv...)
	for i := 0; i < 8; i++ {
		n[11-i] ^= byte(e.seq >> (8 * i))
	}
	return n
}
func (e *epoch) open(header, body []byte) ([]byte, error) {
	p, err := e.aead.Open(nil, e.nonce(), body, header)
	if err == nil {
		e.seq++
	}
	return p, err
}
func (e *epoch) write(c net.Conn, p []byte, kind byte) error {
	plain := append(append([]byte(nil), p...), kind)
	n := len(plain) + 16
	head := []byte{23, 3, 3, byte(n >> 8), byte(n)}
	record := append(head, e.aead.Seal(nil, e.nonce(), plain, head)...)
	e.seq++
	_, err := c.Write(record)
	return err
}
func (e *epoch) update() error {
	e.secret = expand(e.secret, e.hf, "traffic upd", e.hf().Size())
	return e.setup()
}
func serve(raw net.Conn, cert tls.Certificate) error {
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(10 * time.Second))
	capture := &capturedConn{Conn: raw}
	var secrets bytes.Buffer
	conn := tls.Server(capture, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, KeyLogWriter: &secrets})
	if err := conn.Handshake(); err != nil {
		return err
	}
	request := make([]byte, 47)
	if _, err := io.ReadFull(conn, request); err != nil {
		return err
	}
	var server, client epoch
	server.hf = sha256.New
	server.keylen = 16
	switch conn.ConnectionState().CipherSuite {
	case tls.TLS_AES_128_GCM_SHA256:
	case tls.TLS_AES_256_GCM_SHA384:
		server.hf = sha512.New384
		server.keylen = 32
	default:
		return errors.New("AES oracle cipher required")
	}
	client.hf = server.hf
	client.keylen = server.keylen
	for _, line := range strings.Split(secrets.String(), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		secret, err := hex.DecodeString(fields[2])
		if err != nil {
			return err
		}
		if fields[0] == "SERVER_TRAFFIC_SECRET_0" {
			server.secret = secret
		}
		if fields[0] == "CLIENT_TRAFFIC_SECRET_0" {
			client.secret = secret
		}
	}
	if len(server.secret) != server.hf().Size() || len(client.secret) != client.hf().Size() {
		return errors.New("keylog shape")
	}
	if err := server.setup(); err != nil {
		return err
	}
	if err := client.setup(); err != nil {
		return err
	}
	// Count authenticated application-epoch records emitted by Go itself (tickets),
	// skipping handshake-epoch records by failed AEAD authentication, without keys in logs.
	for p := capture.wire; len(p) > 0; {
		if len(p) < 5 {
			return errors.New("capture header")
		}
		n := int(p[3])<<8 | int(p[4])
		if n+5 > len(p) {
			return errors.New("capture record")
		}
		if p[0] == 23 {
			server.open(p[:5], p[5:5+n])
		}
		p = p[5+n:]
	}
	if err := server.write(raw, []byte{24, 0, 0, 1, 1}, 22); err != nil {
		return err
	}
	if err := server.update(); err != nil {
		return err
	}
	// The driver's only application record is its request at sequence0. The KU
	// response must still authenticate at old client epoch sequence1.
	client.seq = 1
	header := make([]byte, 5)
	if _, err := io.ReadFull(raw, header); err != nil {
		return err
	}
	n := int(header[3])<<8 | int(header[4])
	if n != 22 {
		return errors.New("KU response size")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(raw, body); err != nil {
		return err
	}
	response, err := client.open(header, body)
	if err != nil {
		return errors.New("KU response old epoch authentication")
	}
	if !bytes.Equal(response, []byte{24, 0, 0, 1, 0, 22}) {
		return errors.New("KU response framing")
	}
	reply := append([]byte{0, 0}, request[26:]...)
	if err := server.write(raw, reply, 23); err != nil {
		return err
	}
	return server.write(raw, []byte{1, 0}, 21)
}
func main() {
	if len(os.Args) != 4 {
		panic("mode cert key")
	}
	cert, err := tls.LoadX509KeyPair(os.Args[2], os.Args[3])
	if err != nil {
		panic(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	fmt.Printf("PORT %d\n", ln.Addr().(*net.TCPAddr).Port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			panic(err)
		}
		go func() {
			if err := serve(conn, cert); err != nil && err != io.EOF {
				fmt.Fprintln(os.Stderr, "oracle:", err)
			}
		}()
	}
}
