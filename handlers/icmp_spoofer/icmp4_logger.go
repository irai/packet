package icmp_spoofer

import (
	"fmt"
	"syscall"

	"github.com/irai/packet"
	"golang.org/x/net/ipv4"
)

// Handler4 maintains the underlying socket connection
type Handler4 struct {
	session *packet.Session
}

// New4 creates an ICMPv4 handler
func New4(engine *packet.Session) (h *Handler4, err error) {
	h = &Handler4{session: engine}
	return h, nil
}

// Close terminates all internal goroutines
func (h *Handler4) Close() error {
	return nil
}

// ProcessPacket parses an ICMP4 packet and log the frame.
//
// This is a simple processor to common ICMP4 packets includin
// echo request/reply, destination unreacheable and redirect.
// It does not contain any logic beyond logging.
func (h *Handler4) ProcessPacket(frame packet.Frame) error {
	if frame.PayloadID != packet.PayloadICMP4 {
		return packet.ErrParseProtocol
	}

	ether := frame.Ether()
	// ip4Frame := frame.IP4()
	icmpFrame := packet.ICMP(frame.Payload())
	if err := icmpFrame.IsValid(); err != nil {
		return fmt.Errorf("invalid icmp frame: %w", err)
	}

	switch icmpFrame.Type() {
	case uint8(ipv4.ICMPTypeEchoReply):
		echo := packet.ICMPEcho(icmpFrame)
		if err := echo.IsValid(); err != nil {
			return err
		}
		if Logger4.IsInfo() {
			Logger4.Msg("echo reply recvd").IP("srcIP", frame.SrcAddr.IP).Struct(echo).Write()
		}

	case uint8(ipv4.ICMPTypeEcho):
		echo := packet.ICMPEcho(icmpFrame)
		if Logger4.IsInfo() {
			Logger4.Msg("echo request recvd").IP("srcIP", frame.SrcAddr.IP).Struct(echo).Write()
		}

	case uint8(ipv4.ICMPTypeRedirect):
		if Logger4.IsInfo() {
			Logger4.Msg("icmp4 redirect recv").Struct(ether).IP("srcIP", ether.SrcIP()).IP("dstIP", ether.DstIP()).ByteArray("payload", frame.Payload()).Write()
		}

	case uint8(ipv4.ICMPTypeDestinationUnreachable):
		switch icmpFrame.Code() {
		case 2: // protocol unreachable
		case 3: // port unreachable
		default:
			fmt.Printf("icmp4 : unexpected destination unreachable from ip=%s code=%d\n", frame.SrcAddr.IP, icmpFrame.Code())
		}
		if len(frame.Payload()) < 8+20 { // minimum 8 bytes icmp + 20 ip4
			Logger4.Msg("too short - unreachable packet").IP("srcIP", frame.SrcAddr.IP).Int("len", len(frame.Payload())).Write()
			return packet.ErrParseFrame
		}
		originalIP4Frame := packet.IP4(frame.Payload()[8:]) // ip4 starts after icmp 8 bytes
		if err := originalIP4Frame.IsValid(); err != nil {
			Logger4.Msg("invalid destination unreachable packet").IP("srcIP", frame.SrcAddr.IP).Error(err).Write()
			return packet.ErrParseFrame
		}
		var port uint16
		switch originalIP4Frame.Protocol() {
		case syscall.IPPROTO_UDP:
			udp := packet.UDP(originalIP4Frame.Payload())
			if err := udp.IsValid(); err != nil {
				Logger4.Msg("invalid udp destination unreacheable").IP("srcIP", frame.SrcAddr.IP).Error(err).Write()
				return err
			}
			port = udp.DstPort()
		case syscall.IPPROTO_TCP:
			tcp := packet.TCP(originalIP4Frame.Payload())
			if err := tcp.IsValid(); err != nil {
				Logger4.Msg("invalid tcp destination unreacheable").IP("srcIP", frame.SrcAddr.IP).Error(err).Write()
				return packet.ErrParseFrame
			}
			port = tcp.DstPort()
		}
		if Logger4.IsInfo() {
			Logger4.Msg("destination unreacheable").MAC("srcMAC", ether.Src()).MAC("dstMAC", ether.Dst()).IP("srcIP", ether.SrcIP()).IP("dstIP", ether.DstIP()).
				Uint8("code", icmpFrame.Code()).IP("origIP", originalIP4Frame.Dst()).Uint16Hex("origPort", port).Write()
		}

	default:
		Logger4.Msg("not implemented").Uint8("type", icmpFrame.Type()).Bytes("frame", icmpFrame).Write()
	}
	return nil
}
