package icmp4

import (
	"fmt"
	"time"

	"github.com/irai/packet"
)

// Debug packets turn on logging if desirable
var Debug bool

var _ packet.PacketProcessor = &Handler{}

// Handler maintains the underlying socket connection
type Handler struct {
	// NICInfo *packet.NICInfo
	// conn    net.PacketConn
	engine *packet.Handler
}

// Attach create a ICMPv4 handler and attach to the engine
func Attach(engine *packet.Handler) (h *Handler, err error) {
	h = &Handler{engine: engine}
	h.engine.HandlerICMP4 = h

	return h, nil
}

// Detach remove the plugin from the engine
func (h *Handler) Detach() error {
	h.engine.HandlerICMP4 = packet.PacketNOOP{}
	return nil
}

// Start implements PacketProcessor interface
func (h *Handler) Start() error {
	return nil
}

// Stop implements PacketProcessor interface
func (h *Handler) Stop() error {
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

func (h *Handler) ProcessPacket(host *packet.Host, b []byte, header []byte) (*packet.Host, packet.Result, error) {

	icmpFrame := packet.ICMP4(header)

	switch icmpFrame.Type() {
	case packet.ICMPTypeEchoReply:

		// ICMPEcho start from icmp frame
		echo := packet.ICMPEcho(icmpFrame)
		if !echo.IsValid() {
			fmt.Println("icmp4: invalid echo reply", icmpFrame, len(icmpFrame))
			return host, packet.Result{}, fmt.Errorf("icmp invalid icmp4 packet")
		}
		if Debug {
			fmt.Printf("icmp4: echo reply rcvd %s\n", echo)
		}
		echoNotify(echo.EchoID()) // unblock ping if waiting

	case packet.ICMPTypeEchoRequest:
		echo := packet.ICMPEcho(icmpFrame)
		if Debug {
			fmt.Printf("icmp4: echo request rcvd%s\n", echo)
		}

	default:
		fmt.Printf("icmp4 not implemented type=%d: frame:0x[% x]\n", icmpFrame.Type(), icmpFrame)
	}
	return host, packet.Result{}, nil
}
