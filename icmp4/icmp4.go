package icmp4

import (
	"fmt"
	"syscall"
	"time"

	"github.com/irai/packet"
	"golang.org/x/net/ipv4"
)

// Debug packets turn on logging if desirable
var Debug bool

type ICMP4Handler interface {
	packet.PacketProcessor
	Ping(srcAddr packet.Addr, dstAddr packet.Addr, timeout time.Duration) (err error)
}

type ICMP4NOOP struct {
}

func (p ICMP4NOOP) Start() error { return nil }
func (p ICMP4NOOP) Stop() error  { return nil }
func (p ICMP4NOOP) ProcessPacket(*packet.Host, []byte, []byte) (packet.Result, error) {
	return packet.Result{}, nil
}
func (p ICMP4NOOP) StartHunt(addr packet.Addr) (packet.HuntStage, error) {
	return packet.StageNoChange, nil
}
func (p ICMP4NOOP) StopHunt(addr packet.Addr) (packet.HuntStage, error) {
	return packet.StageNoChange, nil
}
func (p ICMP4NOOP) CheckAddr(addr packet.Addr) (packet.HuntStage, error) {
	return packet.StageNoChange, nil
}
func (p ICMP4NOOP) MinuteTicker(now time.Time) error { return nil }
func (p ICMP4NOOP) Close() error                     { return nil }
func (p ICMP4NOOP) Ping(srcAddr packet.Addr, dstAddr packet.Addr, timeout time.Duration) error {
	return nil
}

var _ ICMP4Handler = &Handler{}

// Handler maintains the underlying socket connection
type Handler struct {
	session *packet.Session
}

// New create a ICMPv4 handler and attach to the engine
func New(engine *packet.Session) (h *Handler, err error) {
	h = &Handler{session: engine}
	// h.engine.HandlerICMP4 = h

	return h, nil
}

// Close remove the plugin from the engine
func (h *Handler) Close() error {
	// h.engine.HandlerICMP4 = packet.PacketNOOP{}
	return nil
}

// Start implements PacketProcessor interface
func (h *Handler) Start() error {
	return nil
}

// Stop implements PacketProcessor interface
func (h *Handler) Stop() error {
	h.Close()
	return nil
}

// MinuteTicker implements packet processor interface
func (h *Handler) MinuteTicker(now time.Time) error {
	return nil
}

// StartHunt implements PacketProcessor interface
func (h *Handler) StartHunt(addr packet.Addr) (packet.HuntStage, error) {
	return packet.StageHunt, nil
}

// StopHunt implements PacketProcessor interface
func (h *Handler) StopHunt(addr packet.Addr) (packet.HuntStage, error) {
	return packet.StageNormal, nil
}

func (h *Handler) ProcessPacket(host *packet.Host, p []byte, header []byte) (packet.Result, error) {

	ether := packet.Ether(p)
	ip4Frame := packet.IP4(ether.Payload())
	icmpFrame := packet.ICMP4(header)

	switch icmpFrame.Type() {
	case packet.ICMPTypeEchoReply:

		// ICMPEcho start from icmp frame
		echo := packet.ICMPEcho(icmpFrame)
		if !echo.IsValid() {
			fmt.Println("icmp4: invalid echo reply", icmpFrame, len(icmpFrame))
			return packet.Result{}, fmt.Errorf("icmp invalid icmp4 packet")
		}
		if Debug {
			fmt.Printf("icmp4: echo reply from ip=%s %s\n", ip4Frame.Src(), echo)
		}
		echoNotify(echo.EchoID()) // unblock ping if waiting

	case packet.ICMPTypeEchoRequest:
		echo := packet.ICMPEcho(icmpFrame)
		if Debug {
			fmt.Printf("icmp4: echo request from ip=%s %s\n", ip4Frame.Src(), echo)
		}

	case uint8(ipv4.ICMPTypeDestinationUnreachable):
		switch icmpFrame.Code() {
		case 2: // protocol unreachable
		case 3: // port unreachable
		default:
			fmt.Printf("icmp4 : unexpected destination unreachable from ip=%s code=%d\n", ip4Frame.Src(), icmpFrame.Code())
		}
		if len(header) < 8+20 { // minimum 8 bytes icmp + 20 ip4
			fmt.Println("icmp4 : invalid destination unreachable packet", ip4Frame.Src(), len(header))
			return packet.Result{}, packet.ErrParseFrame
		}
		originalIP4Frame := packet.IP4(header[8:]) // ip4 starts after icmp 8 bytes
		if !originalIP4Frame.IsValid() {
			fmt.Println("icmp4 : invalid destination unreachable packet", ip4Frame.Src(), len(header))
			return packet.Result{}, packet.ErrParseFrame
		}
		var port uint16
		switch originalIP4Frame.Protocol() {
		case syscall.IPPROTO_UDP:
			udp := packet.UDP(originalIP4Frame.Payload())
			if !udp.IsValid() {
				fmt.Println("icmp4 : invalid upd destination unreacheable", ip4Frame.Src(), originalIP4Frame)
				return packet.Result{}, packet.ErrParseFrame
			}
			port = udp.DstPort()
		case syscall.IPPROTO_TCP:
			tcp := packet.TCP(originalIP4Frame.Payload())
			if !tcp.IsValid() {
				fmt.Println("icmp4 : invalid tcp destination unreacheable", ip4Frame.Src(), originalIP4Frame)
				return packet.Result{}, packet.ErrParseFrame
			}
			port = tcp.DstPort()
		}
		fmt.Printf("icmp4 : destination unreacheable from ip=%s failIP=%s failPort=%d code=%d\n", ip4Frame.Src(), originalIP4Frame.Dst(), port, icmpFrame.Code())

	default:
		fmt.Printf("icmp4 not implemented type=%d: frame:0x[% x]\n", icmpFrame.Type(), icmpFrame)
	}
	return packet.Result{}, nil
}
