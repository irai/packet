package icmp4

import (
	"fmt"
	"sync"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/model"
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
	msgRecv bool
	expire  time.Time
	wakeup  chan bool
}

var icmpTable = struct {
	sync.Mutex
	table map[uint16]*icmpEntry // must use pointer because of channel in struct
}{
	table: make(map[uint16]*icmpEntry),
}

// SendEchoRequest transmit an icmp echo request
// Do not wait for response
func (h *Handler) SendEchoRequest(srcAddr model.Addr, dstAddr model.Addr, id uint16, seq uint16) error {
	if srcAddr.IP.To4() == nil || dstAddr.IP.To4() == nil {
		return packet.ErrInvalidIP
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

	if Debug {
		fmt.Printf("icmp4: echo request %s\n", packet.ICMPEcho(p))
	}
	return h.sendPacket(srcAddr, dstAddr, p)
}

func echoNotify(id uint16) {
	icmpTable.Lock()
	if len(icmpTable.table) <= 0 {
		icmpTable.Unlock()
		return
	}

	if entry, ok := icmpTable.table[id]; ok {
		entry.msgRecv = true
		entry.wakeup <- true
	}
	icmpTable.Unlock()
}

// Ping send a ping request and wait for a reply
func (h *Handler) Ping(srcAddr model.Addr, dstAddr model.Addr, timeout time.Duration) (err error) {
	if timeout <= 0 || timeout > time.Second*10 {
		timeout = time.Second * 2
	}

	msg := icmpEntry{expire: time.Now().Add(timeout), wakeup: make(chan bool)}
	id := uint16(time.Now().Nanosecond())
	seq := uint16(1)

	icmpTable.Lock()
	icmpTable.table[id] = &msg
	icmpTable.Unlock()

	if err = h.SendEchoRequest(srcAddr, dstAddr, id, seq); err != nil {
		return err
	}

	for {
		icmpTable.Lock()
		if msg.msgRecv || msg.expire.Before(time.Now()) {
			break
		}
		icmpTable.Unlock()
		select {
		case <-msg.wakeup:
		case <-time.After(timeout):
		}
	}

	// loop finishes with lock
	delete(icmpTable.table, id)
	icmpTable.Unlock()

	if !msg.msgRecv {
		return packet.ErrTimeout
	}

	return nil
}

// CheckAddr validates the default route is pointing to us by pinging
// client using home router IP as source IP. The reply will come to us
// when the default route on client is netfilter. If not, the ping
// reply will not be received.
//
// Note: the reply will also come to us if the client is undergoing
// an arp attack (hunt).
func (h *Handler) CheckAddr(addr model.Addr) (model.HuntStage, error) {
	// Test if client is online first
	// If client does not respond to echo, there is little we can test
	if err := h.Ping(model.Addr{MAC: h.engine.NICInfo.HostMAC, IP: h.engine.NICInfo.HostIP4.IP}, addr, time.Second*2); err != nil {
		fmt.Printf("icmp4 : not responding to ping ip=%s mac=%s\n", addr.IP, addr.MAC)
		return model.StageNormal, packet.ErrTimeout
	}

	// first attempt
	err := h.Ping(model.Addr{MAC: h.engine.NICInfo.RouterMAC, IP: h.engine.NICInfo.RouterIP4.IP}, addr, time.Second*2)
	if err == nil {
		return model.StageRedirected, nil
	}

	// second attempt
	err = h.Ping(model.Addr{MAC: h.engine.NICInfo.RouterMAC, IP: h.engine.NICInfo.RouterIP4.IP}, addr, time.Second*2)
	if err == nil {
		return model.StageRedirected, nil
	}

	return model.StageHunt, packet.ErrNotRedirected
}
