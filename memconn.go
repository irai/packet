package packet

import (
	"context"
	"fmt"
	"net"
	"time"
)

// bufferPacketConn is a net.PacketConn pipe to enable testing
type bufferedPacketConn struct {
	conn    net.Conn
	reading bool
}

// TestNewBufferedConn create a mem conn for testing
func TestNewBufferedConn() (a *bufferedPacketConn, b *bufferedPacketConn) {
	a = &bufferedPacketConn{}
	b = &bufferedPacketConn{}
	a.conn, b.conn = net.Pipe()
	a.reading = true // assume a is the main server read/write; b is the client
	return a, b
}

func (p *bufferedPacketConn) Close() error {
	return p.conn.Close()
}

func (p *bufferedPacketConn) LocalAddr() net.Addr                { return nil }
func (p *bufferedPacketConn) SetDeadline(t time.Time) error      { return nil }
func (p *bufferedPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (p *bufferedPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func (p *bufferedPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	p.reading = true
	n, err := p.conn.Read(b)
	return n, nil, err
}

func (p *bufferedPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if !p.reading {
		panic("buffered conn writing without read will block forever")
	}
	n, err := p.conn.Write(b)
	return n, err
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
			fmt.Printf("raw: got buffere msg=%s\n", ether)
		}
	}
}
