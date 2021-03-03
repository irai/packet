package icmp4

import (
	"sync"
	"time"

	"github.com/irai/packet"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	icmpv4EchoRequest = 8
	icmpv4EchoReply   = 0
	icmpv6EchoRequest = 128
	icmpv6EchoReply   = 129
)

type icmpEntry struct {
	msgRecv packet.ICMPEcho
	expire  time.Time
}

var icmpTable = struct {
	mutex sync.Mutex
	cond  *sync.Cond
	table map[uint16]*icmpEntry
}{
	table: make(map[uint16]*icmpEntry),
}

func init() {
	icmpTable.cond = sync.NewCond(&icmpTable.mutex)
}

// SendEchoRequest transmit an icmp echo request
// Do not wait for response
func (h *Handler) SendEchoRequest(srcAddr packet.Addr, dstAddr packet.Addr, id uint16, seq uint16) error {
	if srcAddr.IP.To4() == nil || dstAddr.IP.To4() == nil {
		return packet.ErrInvalidIP4
	}
	icmpMessage := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
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

	return h.sendPacket(srcAddr, dstAddr, p)
}

// Ping send a ping request and wait for a reply
func (h *Handler) Ping(srcAddr packet.Addr, dstAddr packet.Addr, timeout time.Duration) (err error) {
	if timeout <= 0 || timeout > time.Second*10 {
		timeout = time.Second * 2
	}
	icmpTable.cond.L.Lock()
	msg := icmpEntry{expire: time.Now().Add(timeout)}
	id := uint16(time.Now().Nanosecond())
	seq := uint16(1)
	icmpTable.table[id] = &msg
	icmpTable.cond.L.Unlock()

	if err = h.SendEchoRequest(srcAddr, dstAddr, id, seq); err != nil {
		// log.Error("error sending ping packet", err)
		return err
	}

	// wait with mutex locked
	icmpTable.cond.L.Lock()
	for msg.msgRecv == nil && msg.expire.After(time.Now()) {
		go func() { time.Sleep(timeout); icmpTable.cond.Broadcast() }() // wake up in timeout if not before
		icmpTable.cond.Wait()
	}
	delete(icmpTable.table, id)
	icmpTable.cond.L.Unlock()

	if msg.msgRecv == nil {
		return packet.ErrTimeout
	}

	return nil
}
