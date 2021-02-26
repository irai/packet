package icmp4

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/raw"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"

	"golang.org/x/net/icmp"
)

// Debug packets turn on logging if desirable
var Debug bool

var _ raw.PacketProcessor = &Handler{}

// Handler maintains the underlying socket connection
type Handler struct {
	NICInfo *raw.NICInfo
	conn    net.PacketConn
}

func (h *Handler) sendPacket(srcAddr raw.Addr, dstAddr raw.Addr, p raw.ICMP4) error {

	// TODO: reuse h.conn and write directly to socket
	c, err := net.ListenPacket("ip4:1", "0.0.0.0") // ICMP for IPv4
	if err != nil {
		log.Error("icmp error in listen packet: ", err)
		return err
	}
	defer c.Close()

	r, err := ipv4.NewRawConn(c)
	if err != nil {
		log.Error("icmp error in newrawconn: ", err)
		return err
	}

	iph := &ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TOS:      0xc0, // DSCP CS6
		TotalLen: ipv4.HeaderLen + len(p),
		TTL:      10,
		Protocol: 1,
		Src:      srcAddr.IP,
		Dst:      dstAddr.IP,
	}

	if Debug {
		log.WithFields(log.Fields{"group": "icmp", "src": srcAddr, "dst": dstAddr}).Debugf("icmp send msg type=%v", p.Type())
	}
	if err := r.WriteTo(iph, p, nil); err != nil {
		log.Error("icmp failed to write ", err)
		return err
	}

	return nil
}

// New returns an ICMPv4 handler
func New(info *raw.NICInfo, conn net.PacketConn, hosts *raw.HostTable) (h *Handler, err error) {
	h = &Handler{}
	h.NICInfo = info

	return h, nil
}

// Close the underlaying socket
func (h *Handler) Close() error {
	if h.conn != nil {
		return h.conn.Close()
	}
	return nil
}

// Start implements PacketProcessor interface
func (h *Handler) Start(ctx context.Context) error {
	return nil
}

// Stop implements PacketProcessor interface
func (h *Handler) Stop() error {
	return nil
}

// StartHunt implements PacketProcessor interface
func (h *Handler) StartHunt(mac net.HardwareAddr) error {
	return nil
}

// StopHunt implements PacketProcessor interface
func (h *Handler) StopHunt(mac net.HardwareAddr) error {
	return nil
}

func (h *Handler) ProcessPacket(host *raw.Host, b []byte) (*raw.Host, error) {

	icmpFrame := raw.ICMP4(b)

	switch icmpFrame.Type() {
	case raw.ICMPTypeEchoReply:
		if Debug {
			fmt.Printf("icmp4 rcvd: %s", icmpFrame)
		}
		icmpTable.cond.L.Lock()
		if len(icmpTable.table) <= 0 {
			icmpTable.cond.L.Unlock()
			// log.Info("no waiting")
			return host, nil
		}
		icmpTable.cond.L.Unlock()

		// parse message - create a copy
		icmpMsg, err := icmp.ParseMessage(1, b)
		if err != nil {
			return host, fmt.Errorf("icmp invalid icmp4 packet: %w ", err)
		}

		icmpTable.cond.L.Lock()
		echo := raw.ICMPEcho(icmpFrame)
		entry, ok := icmpTable.table[echo.EchoID()]
		if ok {
			entry.msgRecv = icmpMsg
			// log.Info("wakingup", icmpFrame.EchoID)
		}
		icmpTable.cond.L.Unlock()
		icmpTable.cond.Broadcast()

	case raw.ICMPTypeEchoRequest:
		if Debug {
			log.WithFields(log.Fields{"group": "icmp", "type": icmpFrame.Type(), "code": icmpFrame.Code()}).Debugf("rcvd unimplemented icmp packet % X ", icmpFrame.Payload())
		}

	default:
		fmt.Printf("icmp4 not implemented type=%d: frame:0x[% x]\n", icmpFrame.Type(), icmpFrame)
	}
	return host, nil
}

func (h *Handler) ListenAndServe(ctxt context.Context, pt *packet.Handler) (err error) {

	bpf, err := bpf.Assemble([]bpf.Instruction{
		// Check EtherType
		bpf.LoadAbsolute{Off: 12, Size: 2},
		// 80221Q?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: syscall.ETH_P_8021Q, SkipFalse: 1}, // EtherType is 2 pushed out by two bytes
		bpf.LoadAbsolute{Off: 14, Size: 2},
		// IPv4 && ICMPv4?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: syscall.ETH_P_IP, SkipFalse: 4},
		bpf.LoadAbsolute{Off: 14 + 9, Size: 1},                // IPv4 Protocol field - 14 Eth bytes + 9 IPv4 header
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 1, SkipFalse: 1}, // ICMPv4 protocol - 1
		bpf.RetConstant{Val: 1540},                            // matches ICMPv4, accept up to 1540 (1500 payload + ether header)
		bpf.RetConstant{Val: 0},
		// IPv6 && ICMPv6?
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: syscall.ETH_P_IPV6, SkipFalse: 3},
		bpf.LoadAbsolute{Off: 14 + 6, Size: 1},                 // IPv6 Protocol field - 14 Eth bytes + 6 IPv6 header
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 58, SkipFalse: 1}, // ICMPv6 protocol - 58
		bpf.RetConstant{Val: 1540},                             // matches ICMPv6, accept up to 1540 (1500 payload + ether header)
		bpf.RetConstant{Val: 0},
	})
	if err != nil {
		log.Fatal("bpf assemble error", err)
	}

	h.conn, err = raw.NewServerConn(h.NICInfo.IFI, syscall.ETH_P_IP, raw.Config{Filter: bpf})
	if err != nil {
		h.conn = nil // on windows, not impleted returns a partially completed conn
		return fmt.Errorf("raw.ListenPacket error: %w", err)
	}
	defer h.conn.Close()

	buf := make([]byte, h.NICInfo.IFI.MTU)
	for {
		if err = h.conn.SetReadDeadline(time.Now().Add(time.Second * 2)); err != nil {
			if ctxt.Err() != context.Canceled {
				return fmt.Errorf("setReadDeadline error: %w", err)
			}
			return
		}

		n, _, err1 := h.conn.ReadFrom(buf)
		if err1 != nil {
			if err1, ok := err1.(net.Error); ok && err1.Temporary() {
				continue
			}
			icmpTable.cond.Broadcast() // wakeup all goroutines
			if ctxt.Err() != context.Canceled {
				return fmt.Errorf("read error: %w", err1)
			}
			return
		}

		ether := raw.Ether(buf[:n])
		if ether.EtherType() != syscall.ETH_P_IP || !ether.IsValid() {
			log.Error("icmp invalid ethernet packet ", ether.EtherType())
			continue
		}

		ipFrame := raw.IP4(ether.Payload())
		if !ipFrame.IsValid() {
			log.Error("icmp invalid ip packet ", ether.EtherType())
			continue
		}

		// only interested in ICMP packets; wwithout BPF we also receive UDP and TCP packets
		if ipFrame.Protocol() != 1 { // ICMPv4 = 1
			log.Error("icmp ignore protocol ", ipFrame)
			continue
		}

		host, _ := pt.LANHosts.FindOrCreateHost(ether.Src(), ipFrame.Src())
		h.ProcessPacket(host, ipFrame.Payload())
	}
}
