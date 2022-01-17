package icmp

import (
	"fmt"
	"syscall"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/fastlog"
	"golang.org/x/net/ipv4"
)

type ICMP4Handler interface {
	Start() error
	Stop() error
	ProcessPacket(host *packet.Host, p []byte, header []byte) (packet.Result, error)
	StartHunt(packet.Addr) (packet.HuntStage, error)
	StopHunt(packet.Addr) (packet.HuntStage, error)
	CheckAddr(packet.Addr) (packet.HuntStage, error)
	MinuteTicker(time.Time) error
	Ping(dstAddr packet.Addr, timeout time.Duration) (err error)
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
func (p ICMP4NOOP) Ping(dstAddr packet.Addr, timeout time.Duration) error {
	return nil
}

var _ ICMP4Handler = &Handler4{}

// Handler maintains the underlying socket connection
type Handler4 struct {
	session *packet.Session
}

// New create a ICMPv4 handler and attach to the engine
func New4(engine *packet.Session) (h *Handler4, err error) {
	h = &Handler4{session: engine}
	// h.engine.HandlerICMP4 = h

	return h, nil
}

// Close remove the plugin from the engine
func (h *Handler4) Close() error {
	// h.engine.HandlerICMP4 = packet.PacketNOOP{}
	return nil
}

// Start implements PacketProcessor interface
func (h *Handler4) Start() error {
	return nil
}

// Stop implements PacketProcessor interface
func (h *Handler4) Stop() error {
	h.Close()
	return nil
}

// MinuteTicker implements packet processor interface
func (h *Handler4) MinuteTicker(now time.Time) error {
	return nil
}

// StartHunt implements PacketProcessor interface
func (h *Handler4) StartHunt(addr packet.Addr) (packet.HuntStage, error) {
	return packet.StageHunt, nil
}

// StopHunt implements PacketProcessor interface
func (h *Handler4) StopHunt(addr packet.Addr) (packet.HuntStage, error) {
	return packet.StageNormal, nil
}

func (h *Handler4) ProcessPacket(host *packet.Host, p []byte, header []byte) (packet.Result, error) {

	ether := packet.Ether(p)
	ip4Frame := packet.IP4(ether.Payload())
	icmpFrame := packet.ICMP(header)

	switch icmpFrame.Type() {
	case uint8(ipv4.ICMPTypeEchoReply):

		// ICMPEcho start from icmp frame
		echo := packet.ICMPEcho(icmpFrame)
		if err := echo.IsValid(); err != nil {
			return packet.Result{}, err
		}
		if Debug {
			fastlog.NewLine(module4, "echo reply recvd").IP("srcIP", ip4Frame.Src()).Struct(echo).Write()
		}
		echoNotify(echo.EchoID()) // unblock ping if waiting

	case uint8(ipv4.ICMPTypeEcho):
		echo := packet.ICMPEcho(icmpFrame)
		if Debug {
			fastlog.NewLine(module4, "echo request recvd").IP("srcIP", ip4Frame.Src()).Struct(echo).Write()
		}

	case uint8(ipv4.ICMPTypeRedirect):
		fastlog.NewLine(module4, "icmp4 redirect recv").Struct(ether).IP("srcIP", ether.SrcIP()).IP("dstIP", ether.DstIP()).ByteArray("payload", header).Write()

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
		if err := originalIP4Frame.IsValid(); err != nil {
			fmt.Println("icmp4 : invalid destination unreachable packet", ip4Frame.Src(), len(header), err)
			return packet.Result{}, packet.ErrParseFrame
		}
		var port uint16
		switch originalIP4Frame.Protocol() {
		case syscall.IPPROTO_UDP:
			udp := packet.UDP(originalIP4Frame.Payload())
			if err := udp.IsValid(); err != nil {
				fmt.Println("icmp4 : invalid upd destination unreacheable", ip4Frame.Src(), originalIP4Frame, err)
				return packet.Result{}, err
			}
			port = udp.DstPort()
		case syscall.IPPROTO_TCP:
			tcp := packet.TCP(originalIP4Frame.Payload())
			if err := tcp.IsValid(); err != nil {
				fmt.Println("icmp4 : invalid tcp destination unreacheable", ip4Frame.Src(), originalIP4Frame, err)
				return packet.Result{}, packet.ErrParseFrame
			}
			port = tcp.DstPort()
		}
		fastlog.NewLine(module4, "destination unreacheable").MAC("srcMAC", ether.Src()).MAC("dstMAC", ether.Dst()).IP("srcIP", ether.SrcIP()).IP("dstIP", ether.DstIP()).
			Uint8("code", icmpFrame.Code()).IP("origIP", originalIP4Frame.Dst()).Uint16Hex("origPort", port).Write()

	default:
		fmt.Printf("icmp4 not implemented type=%d: frame:0x[% x]\n", icmpFrame.Type(), icmpFrame)
	}
	return packet.Result{}, nil
}
