package icmp4

import (
	"fmt"
	"net"

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
	h.engine.Lock()
	h.engine.HandlerICMP4 = h
	h.engine.Unlock()

	return h, nil
}

// Detach remove the plugin from the engine
func (h *Handler) Detach() error {
	h.engine.Lock()
	defer h.engine.Unlock()
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

// StartHunt implements PacketProcessor interface
func (h *Handler) StartHunt(mac net.HardwareAddr) error {
	return nil
}

// StopHunt implements PacketProcessor interface
func (h *Handler) StopHunt(mac net.HardwareAddr) error {
	return nil
}

func (h *Handler) ProcessPacket(host *packet.Host, b []byte) (*packet.Host, error) {

	icmpFrame := packet.ICMP4(b)

	switch icmpFrame.Type() {
	case packet.ICMPTypeEchoReply:

		// ICMPEcho start from icmp frame
		echo := packet.ICMPEcho(icmpFrame)
		if !echo.IsValid() {
			fmt.Println("icmp4: invalid echo reply", icmpFrame, len(icmpFrame))
			return host, fmt.Errorf("icmp invalid icmp4 packet")
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
	return host, nil
}
