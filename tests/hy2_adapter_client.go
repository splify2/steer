// SPDX-License-Identifier: GPL-3.0-only
// Disposable loopback oracle, built in pinned Hysteria core module. No Go runtime
// is required by Steer. STEER_LAB_CA_FILE enables normal certificate/name
// verification; the disposable standalone fixture otherwise skips verification.
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"errors"
	hy "github.com/apernet/hysteria/core/v2/client"
	quic "github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
 "reflect"
 "github.com/apernet/hysteria/core/v2/internal/protocol"
	"strings"
	"time"
)

func local(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return host == "localhost" || ip != nil && ip.IsLoopback()
}
func labTLS() *tls.Config {
    config:=&tls.Config{ServerName:"localhost"}
    path:=os.Getenv("STEER_LAB_CA_FILE")
    if path=="" { config.InsecureSkipVerify=true;return config }
    pem,err:=os.ReadFile(path);if err!=nil||len(pem)>1048576 { panic("CA file unavailable") }
    config.RootCAs=x509.NewCertPool();if !config.RootCAs.AppendCertsFromPEM(pem) { panic("invalid CA file") }
    return config
}
// OpenStream is nonblocking. Retry only its typed, recoverable wire-credit
// backpressure on this same connection, with a shared bounded deadline.
func openBounded(c hy.Client,address string,deadline time.Time) (net.Conn,error) {
    pause:=5*time.Millisecond
    for {
        conn,err:=c.TCP(address);if err==nil { return conn,nil }
        var limit *quic.StreamLimitReachedError
        if !errors.As(err,&limit)||!time.Now().Add(pause).Before(deadline) { return nil,err }
        time.Sleep(pause);if pause<80*time.Millisecond { pause*=2 }
    }
}
func main() {
	if (len(os.Args) != 2 && len(os.Args) != 3) || !local(os.Args[1]) {
		panic("loopback server argument required")
	}
	if len(os.Args) == 3 {
		if os.Args[2] != "web" {
			panic("unknown mode")
		}
		tr := &http3.Transport{TLSClientConfig: labTLS()}
		defer tr.Close()
		client := http.Client{Transport: tr, Timeout: 3 * time.Second}
		response, err := client.Get("https://" + os.Args[1] + "/ordinary-web")
		if err != nil {
			panic("HTTP3 web response failed: " + err.Error())
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 8193))
		if err != nil || response.StatusCode != 404 || string(body) != "owned fixture body" {
			panic("borrowed config body lifetime failed")
		}
		fmt.Println("PASS owned web body")
		return
	}
	address, err := net.ResolveUDPAddr("udp", os.Args[1])
	if err != nil {
		panic(err)
	}
	tlsConfig:=labTLS()
	c, info, err := hy.NewClient(&hy.Config{ServerAddr: address, Auth: os.Getenv("STEER_LAB_HY2_TOKEN"),
		TLSConfig: hy.TLSConfig{ServerName: tlsConfig.ServerName, RootCAs:tlsConfig.RootCAs,InsecureSkipVerify: tlsConfig.InsecureSkipVerify}, FastOpen: true})
	if err != nil {
		panic("HY2 handshake failed: " + err.Error())
	}
	defer c.Close()
    if expected:=os.Getenv("STEER_LAB_EXPECT_UDP");expected!="" && (expected=="1")!=info.UDPEnabled { panic("unexpected UDP capability") }
    udpSessions:=map[string]*labUDP{}
    defer func(){for _,u:=range udpSessions { u.close() }}()
	fmt.Println("READY HY2 TCP")
	var held net.Conn
	var filled []net.Conn
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
        if fields[0]=="udp-partials" {
            if len(fields)!=3||!local(fields[2])||udpSessions[fields[1]]!=nil||len(udpSessions)>=16 {panic("bounded UDP partial command")}
            conn,err:=c.UDP();if err!=nil {panic("UDP unavailable")};u:=newLabUDP(conn);udpSessions[fields[1]]=u
            // Pinned oracle-only access to exported fields on its private UDP
            // session. This uses upstream UDPMessage.Serialize/SendDatagram,
            // never the Steer encoder. No Go runtime exists in the product.
            value:=reflect.ValueOf(conn).Elem();id:=uint32(value.FieldByName("ID").Uint())
            send:=value.FieldByName("SendFunc").Interface().(func([]byte,*protocol.UDPMessage)error)
            buffer:=make([]byte,4096);payload:=make([]byte,1000)
            for i:=0;i<16;i++ {msg:=protocol.UDPMessage{SessionID:id,PacketID:uint16(i+1),FragID:0,FragCount:255,Addr:fields[2],Data:payload};if send(buffer,&msg)!=nil {panic("partial send failed")}}
            fmt.Println("PASS udp-partials");continue
        }
        if fields[0]=="udp-cap" { if !info.UDPEnabled { panic("UDP unavailable") };fmt.Println("PASS udp-cap");continue }
        if fields[0]=="udp-open"||fields[0]=="udp-open-reject"||fields[0]=="udp-send"||fields[0]=="udp-reject" {
            if len(fields)!=4 || !local(fields[2]) { panic("bounded loopback UDP command required") }
            n,err:=strconv.Atoi(fields[3]);if err!=nil||n<0||n>65507 { panic("UDP size") }
            u:=udpSessions[fields[1]]
            if fields[0]=="udp-open"||fields[0]=="udp-open-reject" {
                if u!=nil||len(udpSessions)>=16 { panic("UDP session bound") }
                conn,err:=c.UDP();if err!=nil { panic("UDP open failed") };u=newLabUDP(conn);udpSessions[fields[1]]=u
            }
            if u==nil { panic("UDP session absent") }
            payload:=make([]byte,n);for i:=range payload { payload[i]=byte(i*17) }
            if err:=u.conn.Send(payload,fields[2]);err!=nil { panic("UDP send failed") }
            timeout:=3*time.Second;if fields[0]=="udp-reject"||fields[0]=="udp-open-reject" { timeout=200*time.Millisecond }
            select {
            case result:=<-u.messages:
                if fields[0]=="udp-reject"||fields[0]=="udp-open-reject"||result.err!=nil||!bytes.Equal(result.data,payload)||!local(result.address) { panic("UDP reply mismatch") }
            case <-time.After(timeout):
                if fields[0]!="udp-reject"&&fields[0]!="udp-open-reject" { panic("UDP response timeout") }
            }
            fmt.Println("PASS "+fields[0]);continue
        }
		if fields[0] == "quit" {
			if held != nil {
				held.Close()
			}
			fmt.Println("PASS quit")
			return
		}
		if fields[0] == "send" {
			if held == nil {
				panic("no held flow")
			}
			exchange(held, 32768)
			fmt.Println("PASS send")
			continue
		}
		if fields[0]=="expect-end" {
			if held==nil { panic("no held flow") };held.SetDeadline(time.Now().Add(2*time.Second))
			_,err:=held.Write([]byte{42});if err==nil { var b [1]byte;_,err=held.Read(b[:]) }
			if err==nil { panic("retired flow survived deadline") };fmt.Println("PASS expect-end");continue
		}
		if fields[0] == "drop" {
			if held == nil {
				panic("no held flow")
			}
			held.Close()
			held = nil
			fmt.Println("PASS drop")
			continue
		}
		if fields[0] == "drain" {
			if held == nil {
				panic("no held flow")
			}
			held.SetDeadline(time.Now().Add(3 * time.Second))
			var b [1]byte
			if _, err := io.ReadFull(held, b[:]); err != nil || b[0] != 42 {
				panic("seed echo mismatch")
			}
			fmt.Println("PASS drain")
			continue
		}
		if fields[0] == "drop-filled" {
			for _, conn := range filled {
				conn.Close()
			}
			filled = nil
			fmt.Println("PASS drop-filled")
			continue
		}
		if len(fields) < 2 || !local(fields[1]) {
			panic("loopback target required")
		}
		if fields[0] == "capacity" {
			for i := 0; i < 64; i++ {
				conn, err := c.TCP(fields[1])
				if err != nil {
					break
				}
				conn.SetDeadline(time.Now().Add(time.Second))
				var b [1]byte
				b[0] = 42
				if _, err = conn.Write(b[:]); err == nil {
					_, err = io.ReadFull(conn, b[:])
				}
				if err != nil {
					conn.Close()
					break
				}
				filled = append(filled, conn)
			}
			if len(filled) >= 64 {
				panic("unbounded capacity")
			}
			fmt.Printf("PASS capacity %d\n", len(filled))
			continue
		}
		if fields[0]=="recover" {
			if len(fields)!=3 { panic("recover count") };count,err:=strconv.Atoi(fields[2]);if err!=nil||count<1||count>32 { panic("recover count") }
			deadline:=time.Now().Add(2*time.Second)
			for i:=0;i<count;i++ { conn,err:=openBounded(c,fields[1],deadline);if err!=nil { panic("stream credit did not arrive: "+err.Error()) };exchange(conn,1);filled=append(filled,conn) }
			fmt.Printf("PASS recover %d\n",count);continue
		}
		conn, err := openBounded(c,fields[1],time.Now().Add(time.Second))
		if err != nil {
			panic("unexpected immediate TCP error: " + err.Error())
		}
		if fields[0] == "cancel" {
			conn.Close()
			fmt.Println("PASS cancel")
			continue
		}
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		if fields[0]=="flood" {
			if held!=nil { held.Close() };held=conn;held.SetDeadline(time.Now().Add(10*time.Second))
			go func(){ _,_ = io.Copy(conn,bytes.NewReader(bytes.Repeat([]byte{42},8*1024*1024))) }()
			fmt.Println("PASS flood");continue
		}
		if fields[0] == "open" || fields[0] == "queue" {
			if held != nil {
				held.Close()
			}
			held = conn
			data := []byte{42}
			if fields[0] == "queue" {
				data = bytes.Repeat([]byte{42}, 50000)
			}
			if _, err = io.Copy(held, bytes.NewReader(data)); err != nil {
				panic("request write")
			}
			fmt.Println("PASS " + fields[0])
			continue
		}
		if fields[0] == "reject" {
			_, err = conn.Write([]byte{42})
			if err == nil {
				var b [1]byte
				_, err = conn.Read(b[:])
			}
			conn.Close()
			if err == nil {
				panic("rejected flow unexpectedly succeeded")
			}
			fmt.Println("PASS reject")
			continue
		}
		if fields[0] == "hold" {
			if held != nil {
				held.Close()
			}
			held = conn
			exchange(held, 8192)
			fmt.Println("PASS hold")
			continue
		}
		if fields[0] != "echo" || len(fields) != 3 {
			panic("invalid command")
		}
		size, err := strconv.Atoi(fields[2])
		if err != nil || size < 1 || size > 1048576 {
			panic("invalid size")
		}
		exchange(conn, size)
		conn.Close()
		fmt.Println("PASS echo")
	}
	panic("unexpected command EOF")
}
func exchange(conn net.Conn, size int) {
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i * 13)
	}
	write := make(chan error, 1)
	go func() { _, err := io.Copy(conn, bytes.NewReader(data)); write <- err }()
	got := make([]byte, size)
	_, err := io.ReadFull(conn, got)
	if err != nil {
		panic("TCP echo read failed: " + err.Error())
	}
	if err = <-write; err != nil || !bytes.Equal(data, got) {
		panic("TCP echo mismatch")
	}
}

type udpResult struct { data []byte;address string;err error }
type labUDP struct { conn hy.HyUDPConn;messages chan udpResult;done,exited chan struct{} }
func newLabUDP(conn hy.HyUDPConn)*labUDP {
    u:=&labUDP{conn:conn,messages:make(chan udpResult,8),done:make(chan struct{}),exited:make(chan struct{})}
    go func(){defer close(u.exited);for { data,address,err:=conn.Receive();result:=udpResult{append([]byte(nil),data...),address,err};select {case u.messages<-result:case <-u.done:return};if err!=nil{return} }}()
    return u
}
func (u *labUDP)close(){close(u.done);u.conn.Close();select {case <-u.exited:case <-time.After(3*time.Second):panic("UDP receiver did not drain")}}
