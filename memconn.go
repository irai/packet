package packet

import (
	"fmt"
	"net"
	"time"
)

const maxBufSize = 512

// bufferPacketConn is a net.PacketConn pipe to enable testing
type bufferedPacketConn struct {
	clientChan chan []byte
	serverChan chan []byte
}

// TestNewBufferedConn create a mem conn for testing
func TestNewBufferedConn() (a *bufferedPacketConn, b *bufferedPacketConn) {
	a = &bufferedPacketConn{clientChan: make(chan []byte, maxBufSize), serverChan: make(chan []byte, maxBufSize)}
	b = &bufferedPacketConn{clientChan: a.serverChan, serverChan: a.clientChan}
	return a, b
}

func (p *bufferedPacketConn) Close() error {
	close(p.clientChan)
	return nil
}

func (p *bufferedPacketConn) LocalAddr() net.Addr                { return nil }
func (p *bufferedPacketConn) SetDeadline(t time.Time) error      { return nil }
func (p *bufferedPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (p *bufferedPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func (p *bufferedPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	// will lock and wait
	buf := <-p.serverChan
	n := copy(b[:cap(b)], buf)
	return n, nil, nil
}

func (p *bufferedPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if len(p.clientChan) > maxBufSize-1 {
		fmt.Printf("test buffered conn writing is full len=%d", len(p.clientChan))
		return 0, nil
	}
	t := make([]byte, len(b))
	copy(t, b)
	p.clientChan <- t
	return len(b), nil
}

// TestReadAndDiscardLoop is a helper function to cleanup buffer
func TestReadAndDiscardLoop(conn net.PacketConn) error {
	buf := make([]byte, 2000)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return nil
		}
		if n == 0 {
			return nil
		}

		buf = buf[:n]
		ether := Ether(buf)
		if err := ether.IsValid(); err != nil {
			s := fmt.Sprintf("error ether bytes=%d client packet %s", n, ether)
			panic(s)
		}

		// used for debuging - disable to avoid verbose logging
		if false {
			fmt.Printf("raw: got buffer msg=%s\n", ether)
		}
	}
}
