package icmp

import (
	"bytes"
	"fmt"
	"os/exec"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/fastlog"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// SendEchoRequest transmit an icmp echo request
// Do not wait for response
func (h *Handler4) SendEchoRequest(srcAddr packet.Addr, dstAddr packet.Addr, id uint16, seq uint16) error {
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
		fastlog.NewLine(module4, "send echo4 request").IP("srcIP", srcAddr.IP).IP("dstIP", dstAddr.IP).Struct(ICMPEcho(p)).Write()
	}
	return h.sendPacket(srcAddr, dstAddr, p)
}

// Ping send a ping request and wait for a reply
func (h *Handler4) Ping(dstAddr packet.Addr, timeout time.Duration) (err error) {
	return h.ping(h.session.NICInfo.HostAddr4, dstAddr, timeout)
}

func (h *Handler4) ping(srcAddr packet.Addr, dstAddr packet.Addr, timeout time.Duration) (err error) {
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

	if err = h.SendEchoRequest(srcAddr, dstAddr, id, seq); err != nil {
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

// CheckAddr validates the default route is pointing to us by pinging
// client using home router IP as source IP. The reply will come to us
// when the default route on client is netfilter. If not, the ping
// reply will not be received.
//
// Note: the reply will also come to us if the client is undergoing
// an arp attack (hunt).
func (h *Handler4) CheckAddr(addr packet.Addr) (packet.HuntStage, error) {
	// Test if client is online first
	// If client does not respond to echo, there is little we can test
	if err := h.Ping(addr, time.Second*2); err != nil {
		fastlog.NewLine(module4, "not responding to ping").Struct(addr).Write()
		return packet.StageNormal, packet.ErrTimeout
	}

	// first attempt
	err := h.ping(packet.Addr{MAC: h.session.NICInfo.HostMAC, IP: h.session.NICInfo.RouterIP4.IP}, addr, time.Second*2)
	if err == nil {
		return packet.StageRedirected, nil
	}

	// second attempt
	err = h.ping(packet.Addr{MAC: h.session.NICInfo.HostMAC, IP: h.session.NICInfo.RouterIP4.IP}, addr, time.Second*2)
	if err == nil {
		return packet.StageRedirected, nil
	}

	return packet.StageHunt, packet.ErrNotRedirected
}

// ExecPing execute /usr/bin/ping
//
// This is usefull when engine is not yet running and you need to populate the local arp/ndp cache
// If passing an IPv6 LLA, then must pass the scope as in "fe80::1%eth0"
func ExecPing(ip string) (err error) {
	// -w deadline - wait 1 second
	// -i frequency - one request each 0,2 seconds
	// -c count - how many replies to receive before returning (in conjuction with -w)
	cmd := exec.Command("/usr/bin/ping", ip, "-w", "1", "-i", "0.2", "-c", "1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err = cmd.Run(); err != nil {
		fmt.Printf("packet: failed to ping ip=%s error=%s\n", ip, err)
	}
	fmt.Printf("ping: %q\n", stdout.String())
	// fmt.Printf("errs: %q\n", stderr.String())
	return err
}
