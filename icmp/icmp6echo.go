package icmp

import (
	"sync"
	"time"

	"github.com/irai/packet"
)

type icmpEntry struct {
	msgRecv bool
	expire  time.Time
	wakeup  chan bool
}

var icmpTable = struct {
	sync.Mutex
	table map[uint16]*icmpEntry // must use pointer because of channel in struct
	id    uint16
}{
	table: make(map[uint16]*icmpEntry),
	id:    1,
}

func echoNotify(id uint16) {
	icmpTable.Lock()
	if len(icmpTable.table) <= 0 {
		icmpTable.Unlock()
		return
	}

	if entry, ok := icmpTable.table[id]; ok {
		entry.msgRecv = true
		close(entry.wakeup)
		delete(icmpTable.table, id)
	}
	icmpTable.Unlock()
}

// Ping send a ping request and wait for a reply
func (h *Handler6) Ping(srcAddr packet.Addr, dstAddr packet.Addr, timeout time.Duration) (err error) {
	if timeout <= 0 || timeout > time.Second*10 {
		timeout = time.Second * 2
	}
	msg := icmpEntry{expire: time.Now().Add(timeout), wakeup: make(chan bool)}
	seq := uint16(1)

	icmpTable.Lock()
	id := icmpTable.id
	icmpTable.id++
	icmpTable.table[id] = &msg
	icmpTable.Unlock()

	if err = h.session.ICMP6SendEchoRequest(srcAddr, dstAddr, id, seq); err != nil {
		return err
	}

	// wait until chan closed or timeout
	select {
	case <-msg.wakeup:
	case <-time.After(timeout):
	}

	// in case of timeout, the entry still exist
	icmpTable.Lock()
	delete(icmpTable.table, id)
	icmpTable.Unlock()

	if !msg.msgRecv {
		return packet.ErrTimeout
	}
	return nil
}
