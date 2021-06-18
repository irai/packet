package packet

import (
	"context"
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
		panic(fmt.Sprintf("buffered conn writing without read will block forever len=%d", len(p.clientChan)))
	}
	t := make([]byte, len(b))
	copy(t, b)
	p.clientChan <- t
	return len(b), nil
}

// TestReadAndDiscardLoop is a helper function to cleanup buffer
func TestReadAndDiscardLoop(ctx context.Context, conn net.PacketConn) error {
	buf := make([]byte, 2000)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != context.Canceled {
				panic(err)
			}
		}
		if ctx.Err() == context.Canceled {
			return nil
		}

		buf = buf[:n]
		ether := Ether(buf)
		if !ether.IsValid() {
			s := fmt.Sprintf("error ether client packet %s", ether)
			panic(s)
		}

		// used for debuging - disable to avoid verbose logging
		if false {
			fmt.Printf("raw: got buffer msg=%s\n", ether)
		}
	}
}
