package packet

import (
	"context"
	"fmt"
	"net"
	"time"
)

const maxBufSize = 128

// bufferPacketConn is a net.PacketConn pipe to enable testing
type bufferedPacketConn struct {
	bufferChan chan []byte
}

// TestNewBufferedConn create a mem conn for testing
func TestNewBufferedConn() (a *bufferedPacketConn, b *bufferedPacketConn) {
	a = &bufferedPacketConn{bufferChan: make(chan []byte, 128)}
	return a, a
}

func (p *bufferedPacketConn) Close() error {
	close(p.bufferChan)
	return nil
}

func (p *bufferedPacketConn) LocalAddr() net.Addr                { return nil }
func (p *bufferedPacketConn) SetDeadline(t time.Time) error      { return nil }
func (p *bufferedPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (p *bufferedPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func (p *bufferedPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	// will lock and wait
	buf := <-p.bufferChan
	n := copy(b[:cap(b)], buf)
	return n, nil, nil
}

func (p *bufferedPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if len(p.bufferChan) > maxBufSize-1 {
		panic(fmt.Sprintf("buffered conn writing without read will block forever len=%d", len(p.bufferChan)))
	}
	t := make([]byte, len(b))
	copy(t, b)
	p.bufferChan <- t
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
