package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
)

const (
	socks5Version       = 0x05
	methodNoAuth        = 0x00
	methodUserPass      = 0x02
	methodNoAcceptable  = 0xFF
	cmdConnect          = 0x01
	atypIPv4            = 0x01
	atypDomain          = 0x03
	repSuccess          = 0x00
	repFailure          = 0x01
	repHostUnreachable  = 0x04
	repConnRefused      = 0x05
	repCmdNotSupported  = 0x07
	repAddrNotSupported = 0x08
	userPassVersion     = 0x01
)

func main() {
	port := flag.Int("port", 1080, "port to listen on")
	flag.Parse()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", *port, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on :%d", *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	method, err := negotiateAuth(conn)
	if err != nil {
		return
	}

	if method == methodUserPass {
		if err := authenticateUserPass(conn); err != nil {
			return
		}
	}

	target, err := handleConnect(conn)
	if err != nil {
		return
	}
	defer target.Close()

	relay(conn, target)
}

func negotiateAuth(conn net.Conn) (byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, err
	}

	if header[0] != socks5Version {
		return 0, fmt.Errorf("unsupported SOCKS version")
	}

	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return 0, err
	}

	requireAuth := os.Getenv("PROXY_USER") != ""
	selected := byte(methodNoAcceptable)

	for _, m := range methods {
		if requireAuth && m == methodUserPass {
			selected = methodUserPass
			break
		}
		if !requireAuth && m == methodNoAuth {
			selected = methodNoAuth
			break
		}
	}

	if _, err := conn.Write([]byte{socks5Version, selected}); err != nil {
		return 0, err
	}

	if selected == methodNoAcceptable {
		return 0, fmt.Errorf("no acceptable method")
	}

	return selected, nil
}

func authenticateUserPass(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}

	if header[0] != userPassVersion {
		return fmt.Errorf("bad auth version")
	}

	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, username); err != nil {
		return err
	}

	plen := make([]byte, 1)
	if _, err := io.ReadFull(conn, plen); err != nil {
		return err
	}

	password := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}

	status := byte(0x01)
	if string(username) == os.Getenv("PROXY_USER") &&
		string(password) == os.Getenv("PROXY_PASS") {
		status = 0x00
	}

	if _, err := conn.Write([]byte{userPassVersion, status}); err != nil {
		return err
	}

	if status != 0x00 {
		return fmt.Errorf("authentication failed")
	}

	return nil
}

func handleConnect(conn net.Conn) (net.Conn, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	if header[0] != socks5Version {
		sendReply(conn, repFailure)
		return nil, fmt.Errorf("bad version")
	}

	if header[1] != cmdConnect {
		sendReply(conn, repCmdNotSupported)
		return nil, fmt.Errorf("unsupported command")
	}

	var host string

	switch header[3] {
	case atypIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, err
		}
		host = net.IP(addr).String()

	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return nil, err
		}

		domain := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, domain); err != nil {
			return nil, err
		}
		host = string(domain)

	default:
		sendReply(conn, repAddrNotSupported)
		return nil, fmt.Errorf("unsupported address type")
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return nil, err
	}

	port := binary.BigEndian.Uint16(portBuf)
	targetAddr := fmt.Sprintf("%s:%d", host, port)

	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		sendReply(conn, repHostUnreachable)
		return nil, err
	}

	if err := sendReply(conn, repSuccess); err != nil {
		target.Close()
		return nil, err
	}

	return target, nil
}

func sendReply(conn net.Conn, rep byte) error {
	reply := []byte{
		socks5Version,
		rep,
		0x00,
		atypIPv4,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}
	_, err := conn.Write(reply)
	return err
}

func relay(client, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(target, client)
		if tcp, ok := target.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(client, target)
		if tcp, ok := client.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
	}()

	wg.Wait()
}