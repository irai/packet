// +build linux

package engine

// This is file was originally created by Matt Layher
// as part of the raw package github.com/mdlayher/raw

import (
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"

	"github.com/irai/packet"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// Must implement net.PacketConn at compile-time.
var _ net.PacketConn = &packetConn{}

// packetConn is the Linux-specific implementation of net.PacketConn for this
// package.
type packetConn struct {
	ifi *net.Interface
	s   socket
	pbe uint16
}

// socket is an interface which enables swapping out socket syscalls for
// testing.
type socket interface {
	Bind(unix.Sockaddr) error
	Close() error
	GetSockoptTpacketStats(level, name int) (*unix.TpacketStats, error)
	Recvfrom([]byte, int) (int, unix.Sockaddr, error)
	Sendto([]byte, int, unix.Sockaddr) error
	SetSockoptPacketMreq(level, name int, mreq *unix.PacketMreq) error
	SetSockoptSockFprog(level, name int, fprog *unix.SockFprog) error
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// htons converts a short (uint16) from host-to-network byte order.
// Thanks to mikioh for this neat trick:
// https://github.com/mikioh/-stdyng/blob/master/afpacket.go
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

// Dial creates a net.PacketConn which can be used to send and receive
// data at the device driver level.
func Dial(ifi *net.Interface) (*packetConn, error) {

	filename := "eth-packet-socket-client"
	proto := uint16(syscall.ETH_P_ALL)

	fd, err := unix.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(proto)))
	if err != nil {
		return nil, err
	}

	if err := syscall.SetNonblock(fd, true); err != nil {
		return nil, err
	}

	// When using Go 1.12+, the SetNonblock call we just did puts the file
	// descriptor into non-blocking mode. In that case, os.NewFile
	// registers the file descriptor with the runtime poller, which is then
	// used for all subsequent operations.
	//
	// See also: https://golang.org/pkg/os/#NewFile
	f := os.NewFile(uintptr(fd), filename)
	sc, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}

	pc, err := newPacketConn(ifi, &sysSocket{f: f, rc: sc}, htons(proto), nil)
	if err != nil {
		return nil, err
	}

	return pc, nil
}

// NewServerConn creates a net.PacketConn which can be used to send and receive
// data at the device driver level.
func NewServerConn(ifi *net.Interface, proto uint16, cfg SocketConfig) (*packetConn, error) {

	filename := "eth-packet-socket"

	// Open a packet socket using specified socket type. Do not specify
	// a protocol to avoid capturing packets which to not match cfg.Filter.
	// The later call to bind() will set up the correct protocol for us.
	sock, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, err
	}

	if err := unix.SetNonblock(sock, true); err != nil {
		return nil, err
	}

	// When using Go 1.12+, the SetNonblock call we just did puts the file
	// descriptor into non-blocking mode. In that case, os.NewFile
	// registers the file descriptor with the runtime poller, which is then
	// used for all subsequent operations.
	//
	// See also: https://golang.org/pkg/os/#NewFile
	f := os.NewFile(uintptr(sock), filename)
	sc, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}

	// Wrap raw socket in socket interface.
	pc, err := newPacketConn(ifi, &sysSocket{f: f, rc: sc}, htons(proto), cfg.Filter)
	if err != nil {
		return nil, err
	}

	if cfg.Promiscuous {
		if err := pc.SetPromiscuous(true); err != nil {
			return nil, err
		}
	}
	if err := pc.bind(); err != nil {
		return nil, err
	}

	return pc, nil
}

// newPacketConn creates a net.PacketConn using the specified network
// interface, wrapped socket and big endian protocol number.
//
// It is the entry point for tests in this package.
func newPacketConn(ifi *net.Interface, s socket, pbe uint16, filter []bpf.RawInstruction) (*packetConn, error) {
	pc := &packetConn{
		ifi: ifi,
		s:   s,
		pbe: pbe,
	}

	if len(filter) > 0 {
		if err := pc.SetBPF(filter); err != nil {
			return nil, err
		}
	}

	return pc, nil
}

// bind the packet socket to the interface specified by ifi
// packet(7):
//   Only the sll_protocol and the sll_ifindex address fields are used for
//   purposes of binding.
// This overrides the protocol given to socket(AF_PACKET).
func (p *packetConn) bind() error {

	if err := p.s.Bind(&unix.SockaddrLinklayer{Protocol: p.pbe, Ifindex: p.ifi.Index}); err != nil {
		return err
	}
	return nil
}

// ReadFrom implements the net.PacketConn.ReadFrom method.
func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	// Attempt to receive on socket
	n, addr, err := p.s.Recvfrom(b, 0)
	if err != nil {
		return n, nil, err
	}

	// Retrieve hardware address and other information from addr.
	sa, ok := addr.(*unix.SockaddrLinklayer)
	if !ok {
		return n, nil, unix.EINVAL
	}

	// Use length specified to convert byte array into a hardware address slice.
	mac := make(net.HardwareAddr, sa.Halen)
	copy(mac, sa.Addr[:])

	// packet(7):
	//   sll_hatype and sll_pkttype are set on received packets for your
	//   information.
	// TODO(mdlayher): determine if similar fields exist and are useful on
	// non-Linux platforms
	return n, &packet.Addr{
		MAC: mac,
	}, nil
}

// WriteTo implements the net.PacketConn.WriteTo method.
func (p *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	// Ensure correct Addr type.
	a, ok := addr.(*packet.Addr)
	if !ok || a.MAC == nil {
		return 0, unix.EINVAL
	}

	// Convert hardware address back to byte array form.
	var baddr [8]byte
	copy(baddr[:], a.MAC)

	// Send message on socket to the specified hardware address from addr
	// packet(7):
	//   When you send packets it is enough to specify sll_family, sll_addr,
	//   sll_halen, sll_ifindex, and sll_protocol. The other fields should
	//   be 0.
	// In this case, sll_family is taken care of automatically by unix.
	err := p.s.Sendto(b, 0, &unix.SockaddrLinklayer{
		Ifindex:  p.ifi.Index,
		Halen:    uint8(len(a.MAC)),
		Addr:     baddr,
		Protocol: p.pbe,
	})
	return len(b), err
}

// Close closes the connection.
func (p *packetConn) Close() error {
	return p.s.Close()
}

// LocalAddr returns the local network address.
func (p *packetConn) LocalAddr() net.Addr {
	return &packet.Addr{
		MAC: p.ifi.HardwareAddr,
	}
}

// SetDeadline implements the net.PacketConn.SetDeadline method.
func (p *packetConn) SetDeadline(t time.Time) error {
	return p.s.SetDeadline(t)
}

// SetReadDeadline implements the net.PacketConn.SetReadDeadline method.
func (p *packetConn) SetReadDeadline(t time.Time) error {
	return p.s.SetReadDeadline(t)
}

// SetWriteDeadline implements the net.PacketConn.SetWriteDeadline method.
func (p *packetConn) SetWriteDeadline(t time.Time) error {
	return p.s.SetWriteDeadline(t)
}

// SetBPF attaches an assembled BPF program to a raw net.PacketConn.
func (p *packetConn) SetBPF(filter []bpf.RawInstruction) error {
	prog := unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: (*unix.SockFilter)(unsafe.Pointer(&filter[0])),
	}

	err := p.s.SetSockoptSockFprog(
		unix.SOL_SOCKET,
		unix.SO_ATTACH_FILTER,
		&prog,
	)
	if err != nil {
		return os.NewSyscallError("setsockopt", err)
	}
	return nil
}

// SetPromiscuous enables or disables promiscuous mode on the interface, allowing it
// to receive traffic that is not addressed to the interface.
func (p *packetConn) SetPromiscuous(b bool) error {
	mreq := unix.PacketMreq{
		Ifindex: int32(p.ifi.Index),
		Type:    unix.PACKET_MR_PROMISC,
	}

	membership := unix.PACKET_ADD_MEMBERSHIP
	if !b {
		membership = unix.PACKET_DROP_MEMBERSHIP
	}

	return p.s.SetSockoptPacketMreq(unix.SOL_PACKET, membership, &mreq)
}

// sysSocket is the default socket implementation.  It makes use of
// Linux-specific system calls to handle raw socket functionality.
type sysSocket struct {
	f  *os.File
	rc syscall.RawConn
}

func (s *sysSocket) SetDeadline(t time.Time) error {
	return s.f.SetDeadline(t)
}

func (s *sysSocket) SetReadDeadline(t time.Time) error {
	return s.f.SetReadDeadline(t)
}

func (s *sysSocket) SetWriteDeadline(t time.Time) error {
	return s.f.SetWriteDeadline(t)
}

func (s *sysSocket) Bind(sa unix.Sockaddr) error {
	var err error
	cerr := s.rc.Control(func(fd uintptr) {
		err = unix.Bind(int(fd), sa)
	})
	if err != nil {
		return err
	}
	return cerr
}

func (s *sysSocket) Close() error {
	return s.f.Close()
}

func (s *sysSocket) GetSockoptTpacketStats(level, name int) (*unix.TpacketStats, error) {
	var stats *unix.TpacketStats
	var err error
	cerr := s.rc.Control(func(fd uintptr) {
		s, errno := unix.GetsockoptTpacketStats(int(fd), level, name)
		stats = s
		if errno != nil {
			err = os.NewSyscallError("getsockopt", errno)
		}
	})
	if err != nil {
		return stats, err
	}
	return stats, cerr
}

func (s *sysSocket) Recvfrom(p []byte, flags int) (n int, addr unix.Sockaddr, err error) {
	cerr := s.rc.Read(func(fd uintptr) bool {
		n, addr, err = unix.Recvfrom(int(fd), p, flags)
		// When the socket is in non-blocking mode, we might see EAGAIN
		// and end up here. In that case, return false to let the
		// poller wait for readiness. See the source code for
		// internal/poll.FD.RawRead for more details.
		//
		// If the socket is in blocking mode, EAGAIN should never occur.
		return err != unix.EAGAIN
	})
	if err != nil {
		return n, addr, err
	}
	return n, addr, cerr
}

func (s *sysSocket) Sendto(p []byte, flags int, to unix.Sockaddr) error {
	var err error
	cerr := s.rc.Write(func(fd uintptr) bool {
		err = unix.Sendto(int(fd), p, flags, to)
		// See comment in Recvfrom.
		return err != unix.EAGAIN
	})
	if err != nil {
		return err
	}
	return cerr
}

func (s *sysSocket) SetSockoptSockFprog(level, name int, fprog *unix.SockFprog) error {
	var err error
	cerr := s.rc.Control(func(fd uintptr) {
		errno := unix.SetsockoptSockFprog(int(fd), level, name, fprog)
		if errno != nil {
			err = os.NewSyscallError("setsockopt", errno)
		}
	})
	if err != nil {
		return err
	}
	return cerr
}

func (s *sysSocket) SetSockoptPacketMreq(level, name int, mreq *unix.PacketMreq) error {
	var err error
	cerr := s.rc.Control(func(fd uintptr) {
		errno := unix.SetsockoptPacketMreq(int(fd), level, name, mreq)
		if errno != nil {
			err = os.NewSyscallError("setsockopt", errno)
		}
	})
	if err != nil {
		return err
	}
	return cerr
}

// A Config can be used to specify additional options for a Conn.
type SocketConfig struct {
	// Linux only: call socket(7) with SOCK_DGRAM instead of SOCK_RAW.
	// Has no effect on other operating systems.
	LinuxSockDGRAM bool

	// Linux only: do not accumulate packet socket statistic counters.  Packet
	// socket statistics are reset on each call to retrieve them via getsockopt,
	// but this package's default behavior is to continue accumulating the
	// statistics internally per Conn.  To use the Linux default behavior of
	// resetting statistics on each call to Stats, set this value to true.
	NoCumulativeStats bool

	// Linux only: initial filter to apply to the connection. This avoids
	// capturing random packets before SetBPF is called.
	Filter []bpf.RawInstruction

	// BSD only: configure the BPF direction flag to allow selection of inbound
	// only (0 - default) or bidirectional (1) packet processing.
	// Has no effect on other operating systems.
	BPFDirection int

	// Set interface to promiscuous mode
	Promiscuous bool
}
