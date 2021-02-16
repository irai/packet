package raw

import (
	"net"
	"time"
)

// bufferPacketConn is a net.PacketConn pipe to enable testing
type bufferedPacketConn struct {
	conn net.Conn
}

func NewBufferedConn() (a *bufferedPacketConn, b *bufferedPacketConn) {
	a = &bufferedPacketConn{}
	b = &bufferedPacketConn{}
	a.conn, b.conn = net.Pipe()
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
	n, err := p.conn.Read(b)
	return n, nil, err
}

func (p *bufferedPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	n, err := p.conn.Write(b)
	return n, err
}
