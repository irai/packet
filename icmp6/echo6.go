package icmp6

import (
	"fmt"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

const (
	icmpv4EchoRequest = 8
	icmpv4EchoReply   = 0
	icmpv6EchoRequest = 128
	icmpv6EchoReply   = 129
)

type icmpEntry struct {
	msgRecv *icmp.Message
	expire  time.Time
}

var icmpTable = struct {
	echoIdentifier uint16
	mutex          sync.Mutex
	cond           *sync.Cond
	table          map[uint16]*icmpEntry
}{
	echoIdentifier: 5000,
	table:          make(map[uint16]*icmpEntry),
}

func init() {
	icmpTable.cond = sync.NewCond(&icmpTable.mutex)
}

// SendEcho transmit an icmp echo request
// Do not wait for response
func (h *Handler) SendEcho(src net.IP, dst net.IP, id uint16, seq uint16) error {

	icmpMessage := icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest,
		Code: 0,
		Body: &icmp.Echo{
			ID:   int(id),
			Seq:  int(seq),
			Data: []byte("HELLO-R-U-THERE"),
		},
	}

	p, err := icmpMessage.Marshal(nil)
	if err != nil {
		return err
	}

	return sendICMP6Packet(h.ifi, src, dst, p)
}

// Ping send a ping request and wait for a reply
func (h *Handler) Ping(src net.IP, dst net.IP, timeout time.Duration) (err error) {

	icmpTable.cond.L.Lock()
	msg := icmpEntry{expire: time.Now().Add(timeout)}
	id := icmpTable.echoIdentifier
	icmpTable.echoIdentifier++
	icmpTable.table[id] = &msg
	icmpTable.cond.L.Unlock()

	if err = h.SendEcho(src, dst, id, 0); err != nil {
		log.Error("error sending ping packet", err)
		return err
	}

	icmpTable.cond.L.Lock()
	for msg.msgRecv == nil && msg.expire.After(time.Now()) {
		icmpTable.cond.Wait()
	}
	delete(icmpTable.table, id)
	icmpTable.cond.L.Unlock()

	if msg.msgRecv == nil {
		return fmt.Errorf("ping timeout ip= %v id=%v", dst, id)
	}

	return nil
}

func sendICMP6Packet(ifi *net.Interface, src net.IP, dst net.IP, p []byte) error {

	// TODO: reuse h.conn and write directly to socket
	c, err := net.ListenPacket("ip6:ipv6-icmp", "::")
	// c, err := net.DialIP("ip6:1", nil, nil) // ICMP for IPv6
	if err != nil {
		log.Error("icmp error in listen packet: ", err)
		return err
	}
	defer c.Close()

	pc := ipv6.NewPacketConn(c)

	/***
	// Hop limit is always 255, per RFC 4861.
	if err := pc.SetHopLimit(255); err != nil {
		return err
	}
	if err := pc.SetMulticastHopLimit(255); err != nil {
		return err
	}
	***/

	// Calculate and place ICMPv6 checksum at correct offset in all messages.
	if err := pc.SetChecksum(true, 2); err != nil {
		return err
	}

	hopLimit := 64
	if dst.IsLinkLocalUnicast() || dst.IsLinkLocalMulticast() {
		hopLimit = 1
	}

	cm := &ipv6.ControlMessage{
		HopLimit: hopLimit,
		Src:      src,
		IfIndex:  ifi.Index,
	}

	if _, err := pc.WriteTo(p, cm, &net.IPAddr{IP: dst, Zone: ifi.Name}); err != nil {
		log.Error("icmp failed to write ", err)
		return err
	}

	return nil
}
