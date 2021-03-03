package icmp4

import (
	"fmt"
	"net"

	"github.com/irai/packet"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/ipv4"

	"golang.org/x/net/icmp"
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

func (h *Handler) sendPacket(srcAddr packet.Addr, dstAddr packet.Addr, p packet.ICMP4) error {

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

// Open create a ICMPv4 handler and attach to the engine
func Open(engine *packet.Handler) (h *Handler, err error) {
	h = &Handler{engine: engine}
	h.engine.Lock()
	h.engine.HandlerICMP4 = h
	h.engine.Unlock()

	return h, nil
}

// Close remove the plugin from the engine
func (h *Handler) Close() error {
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
		echo := packet.ICMPEcho(icmpFrame)
		entry, ok := icmpTable.table[echo.EchoID()]
		if ok {
			entry.msgRecv = icmpMsg
			// log.Info("wakingup", icmpFrame.EchoID)
		}
		icmpTable.cond.L.Unlock()
		icmpTable.cond.Broadcast()

	case packet.ICMPTypeEchoRequest:
		if Debug {
			log.WithFields(log.Fields{"group": "icmp", "type": icmpFrame.Type(), "code": icmpFrame.Code()}).Debugf("rcvd unimplemented icmp packet % X ", icmpFrame.Payload())
		}

	default:
		fmt.Printf("icmp4 not implemented type=%d: frame:0x[% x]\n", icmpFrame.Type(), icmpFrame)
	}
	return host, nil
}
