// Independent Go TLS/HTTP2 server. Responds only after request EOF.
package main

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

func answer(p []byte) []byte {
	if len(p) < 26 {
		return nil
	}
	return append([]byte{0, 0}, p[26:]...)
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
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	if os.Args[1] == "raw" {
		for {
			raw, e := ln.Accept()
			if e != nil {
				panic(e)
			}
			go func() {
				c := tls.Server(raw, cfg)
				defer c.Close()
				c.SetDeadline(time.Now().Add(10 * time.Second))
				p, e := io.ReadAll(io.LimitReader(c, 4097))
				if e != nil || len(p) > 4096 {
					return
				}
				if _, e = c.Write(answer(p)); e != nil {
					return
				}
				c.CloseWrite()
			}()
		}
	}
	var mu sync.Mutex
	pending := map[string]chan []byte{}
	get := func(key string) chan []byte {
		mu.Lock()
		defer mu.Unlock()
		ch := pending[key]
		if ch == nil {
			ch = make(chan []byte, 1)
			pending[key] = ch
		}
		return ch
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			http.Error(w, "h2 required", 400)
			return
		}
		if r.Method == "GET" {
			select {
			case body := <-get(r.URL.Path):
				w.Write(answer(body))
			case <-r.Context().Done():
			}
			return
		}
		body, e := io.ReadAll(io.LimitReader(r.Body, 4097))
		if e != nil || len(body) > 4096 {
			http.Error(w, "bounded body", 400)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/Tun") {
			if len(body) < 7 {
				http.Error(w, "grpc framing", 400)
				return
			}
			size, n := binary.Uvarint(body[6:])
			if n <= 0 || size != uint64(len(body)-6-n) {
				http.Error(w, "grpc length", 400)
				return
			}
			out := answer(body[6+n:])
			msg := make([]byte, 7+len(out))
			binary.BigEndian.PutUint32(msg[1:5], uint32(len(out)+2))
			msg[5] = 10
			msg[6] = byte(len(out))
			copy(msg[7:], out)
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Trailer", "Grpc-Status")
			w.Write(msg)
			w.Header().Set("Grpc-Status", "0")
			return
		}
		if strings.TrimSuffix(r.URL.Path, "/") == "/lab" {
			w.Write(answer(body))
			return
		}
		select {
		case get(r.URL.Path) <- body:
			w.WriteHeader(200)
		case <-r.Context().Done():
		}
	})
	server := &http.Server{Handler: handler, TLSConfig: cfg, ReadHeaderTimeout: 5 * time.Second}
	if err := server.ServeTLS(ln, "", ""); err != nil {
		panic(err)
	}
}
