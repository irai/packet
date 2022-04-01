package packet

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/irai/packet/fastlog"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	ICMP4TypeEchoReply = 0   // Echo Reply
	ICMP6TypeEchoReply = 129 // Echo Reply
)

// ICMP enable access to ICMP frame without copying
type ICMP []byte

// IsValid validates the packet
// TODO: verify checksum?
func (p ICMP) IsValid() error {
	if len(p) >= 8 {
		return nil
	}
	return fmt.Errorf("icmp header too short len=%d: %w", len(p), ErrFrameLen)
}

func (p ICMP) Type() uint8      { return uint8(p[0]) }
func (p ICMP) Code() uint8      { return p[1] }
func (p ICMP) Checksum() uint16 { return binary.BigEndian.Uint16(p[2:4]) }

// TODO: fix the order
func (p ICMP) SetChecksum(cs uint16) { p[3] = uint8(cs >> 8); p[2] = uint8(cs) }
func (p ICMP) RestOfHeader() []byte  { return p[4:8] }
func (p ICMP) Payload() []byte {
	if len(p) > 8 {
		return p[8:]
	}
	return []byte{}
}

func (p ICMP) String() string {
	return fastlog.NewLine("", "").Struct(p).ToString()
}

// FastLog implements fastlog interface
func (p ICMP) FastLog(line *fastlog.Line) *fastlog.Line {
	line.Uint8("type", p.Type())
	line.Uint8("code", p.Code())
	line.Uint16Hex("checksum", p.Checksum())
	line.Int("len", len(p.Payload()))
	return line
}

type ICMPEcho []byte

func (p ICMPEcho) IsValid() error {
	if len(p) >= 8 {
		return nil
	}
	return fmt.Errorf("icmp echo header too short len=%d: %w", len(p), ErrFrameLen)
}
func (p ICMPEcho) Type() uint8      { return uint8(p[0]) }
func (p ICMPEcho) Code() uint8      { return uint8(p[1]) }
func (p ICMPEcho) Checksum() uint16 { return binary.BigEndian.Uint16(p[2:4]) }
func (p ICMPEcho) EchoID() uint16   { return binary.BigEndian.Uint16(p[4:6]) }
func (p ICMPEcho) EchoSeq() uint16  { return binary.BigEndian.Uint16(p[6:8]) }
func (p ICMPEcho) EchoData() []byte {
	if len(p) > 8 {
		return p[8:]
	}
	return nil
}

func EncodeICMPEcho(b []byte, t uint8, code uint8, id uint16, seq uint16, data []byte) ICMPEcho {
	n := 8 + len(data)
	if n > cap(b) {
		return nil
	}
	b = b[:n]
	b[0] = t
	b[1] = code
	binary.BigEndian.PutUint16(b[2:4], 0)
	binary.BigEndian.PutUint16(b[4:6], id)
	binary.BigEndian.PutUint16(b[6:8], seq)
	copy(b[8:], data)
	return b[:n]
}

func (p ICMPEcho) String() string {
	return fastlog.NewLine("", "").Struct(p).ToString()
}

func (p ICMPEcho) FastLog(line *fastlog.Line) *fastlog.Line {
	line.Uint8("type", p.Type())
	line.Uint8("code", p.Code())
	line.Uint16Hex("checksum", p.Checksum())
	line.Uint16Hex("id", p.EchoID())
	line.Uint16Hex("seq", p.EchoSeq())
	line.ByteArray("data", p.EchoData())
	return line
}

type ICMP4Redirect []byte

/*
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Num Addrs   |Addr Entry Size|           Lifetime            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Router Address[1]                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Preference Level[1]                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Router Address[2]                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Preference Level[2]                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               .                               |
|                               .                               |
|                               .                               |
**/

func (p ICMP4Redirect) IsValid() error {
	if len(p) < 8 || len(p) < 8+int(p.NumAddrs())*int(p.AddrSize())*4 {
		return fmt.Errorf("icmp redirect header too short len=%d: %w", len(p), ErrFrameLen)
	}
	if p[0] != byte(ipv6.ICMPTypeRedirect) {
		return fmt.Errorf("icmp header invalid type=%v: %w", p[0], ErrParseFrame)
	}
	if p.AddrSize() != 4 && p.AddrSize() != 10 {
		return fmt.Errorf("icmp header invalid addr size=%v: %w", p.AddrSize(), ErrParseFrame)
	}
	return nil
}

func (p ICMP4Redirect) Type() uint8      { return uint8(p[0]) }
func (p ICMP4Redirect) Code() byte       { return p[1] }
func (p ICMP4Redirect) Checksum() uint16 { return binary.BigEndian.Uint16(p[2:4]) }
func (p ICMP4Redirect) NumAddrs() uint8  { return p[4] }
func (p ICMP4Redirect) AddrSize() uint8  { return p[5] } // The number of 32-bit words per each router address (ie. 2 for IP4)
func (p ICMP4Redirect) Lifetime() uint16 { return binary.BigEndian.Uint16(p[6:8]) }
func (p ICMP4Redirect) Addrs() []net.IP {
	addr := make([]net.IP, 0, p.NumAddrs())
	for i := 0; i < int(p.NumAddrs()); i++ {
		pos := i * int(p.AddrSize()) * 4
		if p.AddrSize() == 4 {
			addr = append(addr, net.IP(p[pos:pos+4]))
			continue
		}
		addr = append(addr, net.IP(p[pos:pos+16]))
	}
	return addr
}

func (p ICMP4Redirect) String() string {
	return fastlog.NewLine("", "").Struct(p).ToString()
}

func (p ICMP4Redirect) FastLog(line *fastlog.Line) *fastlog.Line {
	line.Uint8("type", p.Type())
	line.Uint8("code", p.Code())
	line.Uint16Hex("checksum", p.Checksum())
	line.Uint8("naddrs", p.NumAddrs())
	line.Uint8("addrsize", p.AddrSize())
	line.Uint16("lifetime", p.Lifetime())
	line.Uint16("lifetime", p.Lifetime())
	line.IPArray("addrs", p.Addrs())
	return line
}

type ICMP6RouterSolicitation []byte

func (p ICMP6RouterSolicitation) IsValid() error {
	if len(p) < 8 {
		return fmt.Errorf("icmp redirect header too short len=%d: %w", len(p), ErrFrameLen)
	}
	if p[0] != byte(ipv6.ICMPTypeRouterSolicitation) {
		return fmt.Errorf("icmp redirect header invalid type=%v: %w", p[0], ErrParseFrame)
	}
	return nil
}

func (p ICMP6RouterSolicitation) Type() uint8   { return uint8(p[0]) }
func (p ICMP6RouterSolicitation) Code() byte    { return p[1] }
func (p ICMP6RouterSolicitation) Checksum() int { return int(binary.BigEndian.Uint16(p[2:4])) }
func (p ICMP6RouterSolicitation) SourceLLA() net.HardwareAddr {
	// RS options may containg a single SourceLLA option
	// len is therefore: 26 = 4 bytes header + 4 bytes reserved + 2 bytes option header + 16 IP bytes SourceLLA option
	if len(p) >= 26 && p[8] == 1 && p[9] == 3 { // type == SourceLLA & 24 bytes len (3 * 8bytes)
		return net.HardwareAddr(p[10 : 10+16])
	}
	return nil
}

func (p ICMP6RouterSolicitation) Options() (NewOptions, error) {
	if len(p) <= 24 {
		return NewOptions{}, nil
	}
	/**
	// SourceLinkAddress is the only valid option for Router Solicitation - RFC4861
	for _, v := range options {
		if slla, ok := v.(*LinkLayerAddress); ok {
			rs.SourceLLA = slla.Addr
		}
	}
	**/
	return newParseOptions(p[24:])
}

func (p ICMP6RouterSolicitation) String() string {
	return fastlog.NewLine("", "").Struct(p).ToString()
}

func (p ICMP6RouterSolicitation) FastLog(line *fastlog.Line) *fastlog.Line {
	line.String("type", "ra")
	line.Uint8("code", p.Code())
	line.MAC("sourceLLA", p.SourceLLA())
	return line
}

type ICMP6RouterAdvertisement []byte

func (p ICMP6RouterAdvertisement) IsValid() error {
	if len(p) >= 16 {
		return nil
	}
	return fmt.Errorf("icmp RA header too short len=%d: %w", len(p), ErrFrameLen)
}
func (p ICMP6RouterAdvertisement) Type() uint8                { return uint8(p[0]) }
func (p ICMP6RouterAdvertisement) Code() byte                 { return p[1] }
func (p ICMP6RouterAdvertisement) Checksum() int              { return int(binary.BigEndian.Uint16(p[2:4])) }
func (p ICMP6RouterAdvertisement) CurrentHopLimit() byte      { return p[4] }
func (p ICMP6RouterAdvertisement) ManagedConfiguration() bool { return (p[5] & 0x80) != 0 }
func (p ICMP6RouterAdvertisement) OtherConfiguration() bool   { return (p[5] & 0x40) != 0 }
func (p ICMP6RouterAdvertisement) HomeAgent() bool            { return (p[5] & 0x20) != 0 } // HomeAgent for mobile IPv6?
func (p ICMP6RouterAdvertisement) Preference() byte           { return (p[5] & 0x18) >> 3 } // Default route preference: 01 High, 00 medium, 11 low, 10 reserved
func (p ICMP6RouterAdvertisement) ProxyFlag() bool            { return (p[5] & 0x04) != 0 } // Experimental ND proxy - proxy ARP like???
func (p ICMP6RouterAdvertisement) Flags() byte                { return p[5] }               // All flags
func (p ICMP6RouterAdvertisement) Lifetime() (seconds uint16) { return binary.BigEndian.Uint16(p[6:8]) }
func (p ICMP6RouterAdvertisement) ReachableTime() (milliseconds uint32) {
	return binary.BigEndian.Uint32(p[8:12])
}
func (p ICMP6RouterAdvertisement) RetransmitTimer() (milliseconds uint32) {
	return binary.BigEndian.Uint32(p[12:16])
}
func (p ICMP6RouterAdvertisement) Options() (NewOptions, error) {
	if len(p) <= 16 {
		return NewOptions{}, nil
	}
	return newParseOptions(p[16:])
}
func (p ICMP6RouterAdvertisement) String() string {
	return fastlog.NewLine("", "").Struct(p).ToString()
}
func (p ICMP6RouterAdvertisement) FastLog(l *fastlog.Line) *fastlog.Line {
	l.String("type", "ra")
	l.Uint8("code", p.Code())
	l.Uint8("hoplim", p.CurrentHopLimit())
	l.Uint8Hex("flags", p.Flags())
	l.Bool("managed", p.ManagedConfiguration())
	l.Bool("other", p.OtherConfiguration())
	l.Uint8("preference", p.Preference())
	l.Uint16("lifetimesec", p.Lifetime())
	l.Uint32("reacheablemsec", p.ReachableTime())
	l.Uint32("retransmitmsec", p.RetransmitTimer())
	return l
}

type ICMP6NeighborAdvertisement []byte

func (p ICMP6NeighborAdvertisement) IsValid() error {
	if len(p) >= 24 {
		return nil
	}
	return fmt.Errorf("icmp NA header too short len=%d: %w", len(p), ErrFrameLen)
}
func (p ICMP6NeighborAdvertisement) Type() uint8     { return uint8(p[0]) }
func (p ICMP6NeighborAdvertisement) Code() byte      { return p[1] }
func (p ICMP6NeighborAdvertisement) Checksum() int   { return int(binary.BigEndian.Uint16(p[2:4])) }
func (p ICMP6NeighborAdvertisement) Router() bool    { return (p[4] & 0x80) != 0 }
func (p ICMP6NeighborAdvertisement) Solicited() bool { return (p[4] & 0x40) != 0 }
func (p ICMP6NeighborAdvertisement) Override() bool  { return (p[4] & 0x20) != 0 }
func (p ICMP6NeighborAdvertisement) TargetAddress() netip.Addr {
	return netip.AddrFrom16(*((*[16]byte)(net.IP(p[8:24]))))
}
func (p ICMP6NeighborAdvertisement) TargetLLA() net.HardwareAddr {
	// TargetLLA option
	if len(p) < 32 || p[24] != 2 || p[25] != 1 { // Option type TargetLLA, len 8 bytes
		return nil
	}
	return net.HardwareAddr(p[26 : 26+6])
}

func (p ICMP6NeighborAdvertisement) String() string {
	return fastlog.NewLine("", "").Struct(p).ToString()
}

// Print implements fastlog interface
func (p ICMP6NeighborAdvertisement) FastLog(line *fastlog.Line) *fastlog.Line {
	line.String("type", "na")
	line.Uint8("code", p.Code())
	line.Bool("override", p.Override())
	line.Bool("solicited", p.Solicited())
	line.Bool("router", p.Solicited())
	line.IP("targetIP", p.TargetAddress())
	line.MAC("targetLLA", p.TargetLLA())
	return line
}

func ICMP6NeighborAdvertisementMarshal(router bool, solicited bool, override bool, targetAddr Addr) []byte {
	b := make([]byte, 32)
	b[0] = byte(ipv6.ICMPTypeNeighborAdvertisement)
	if router {
		b[4] |= (1 << 7)
	}
	if solicited {
		b[4] |= (1 << 6)
	}
	if override {
		b[4] |= (1 << 5)
	}
	s := targetAddr.IP.As16()
	copy(b[8:], s[:])            // target ip address
	b[24] = 2                    // option type 2 - target addr
	b[25] = 1                    // len = 1 (8 bytes)
	copy(b[26:], targetAddr.MAC) // target mac addr
	return b
}

type ICMP6NeighborSolicitation []byte

func (p ICMP6NeighborSolicitation) IsValid() error {
	if len(p) >= 24 {
		return nil
	}
	return fmt.Errorf("icmp NS header too short len=%d: %w", len(p), ErrFrameLen)
}
func (p ICMP6NeighborSolicitation) Type() uint8   { return uint8(p[0]) }
func (p ICMP6NeighborSolicitation) Code() byte    { return p[1] }
func (p ICMP6NeighborSolicitation) Checksum() int { return int(binary.BigEndian.Uint16(p[2:4])) }
func (p ICMP6NeighborSolicitation) TargetAddress() netip.Addr {
	ip, _ := netip.AddrFromSlice(p[8:24])
	return ip
}
func (p ICMP6NeighborSolicitation) SourceLLA() net.HardwareAddr {
	// SourceLLA option
	if len(p) < 32 || p[24] != 1 || p[25] != 1 { // Option type TargetLLA, len 8 bytes
		return nil
	}
	return net.HardwareAddr(p[26 : 26+6])
}

func (p ICMP6NeighborSolicitation) String() string {
	return fastlog.NewLine("", "").Struct(p).ToString()
}

// FastLog implements fastlog interface
func (p ICMP6NeighborSolicitation) FastLog(line *fastlog.Line) *fastlog.Line {
	line.String("type", "ns")
	line.Uint8("code", p.Code())
	line.IP("targetIP", p.TargetAddress())
	line.MAC("sourceLLA", p.SourceLLA())
	return line
}

func ICMP6NeighborSolicitationMarshal(targetAddr netip.Addr, sourceLLA net.HardwareAddr) ([]byte, error) {
	b := make([]byte, 32)                          // 4 header + 28 bytes
	b[0] = byte(ipv6.ICMPTypeNeighborSolicitation) // NS
	// skip reserved 4 bytes
	copy(b[8:], targetAddr.AsSlice())

	// single option: SourceLLA option
	b[24] = 2 // Target option
	b[25] = 1 // len 8 bytes
	copy(b[26:], sourceLLA)
	return b, nil
}

type ICMP6Redirect []byte

func (p ICMP6Redirect) IsValid() error {
	if len(p) >= 40 {
		return nil
	}
	return fmt.Errorf("icmp redirect header too short len=%d: %w", len(p), ErrFrameLen)
}
func (p ICMP6Redirect) Type() uint8           { return uint8(p[0]) }
func (p ICMP6Redirect) Code() byte            { return p[1] }
func (p ICMP6Redirect) Checksum() int         { return int(binary.BigEndian.Uint16(p[2:4])) }
func (p ICMP6Redirect) TargetAddress() net.IP { return net.IP(p[8:24]) }
func (p ICMP6Redirect) DstAddress() net.IP    { return net.IP(p[24:40]) }
func (p ICMP6Redirect) TargetLinkLayerAddr() net.HardwareAddr {
	// TargetLLA option
	if len(p) < 40+8 || p[40] != 2 || p[41] != 1 { // Option type TargetLLA, len 8 bytes
		return nil
	}
	return net.HardwareAddr(p[42 : 42+6])
}
func (p ICMP6Redirect) String() string {
	return fmt.Sprintf("type=na code=%d targetIP=%s targetMAC=%s dstIP=%s", p.Code(), p.TargetAddress(), p.TargetLinkLayerAddr(), p.DstAddress())
}

// ICMP4SendEchoRequest transmit an icmp echo request
// Do not wait for response
func (h *Session) ICMP4SendEchoRequest(srcAddr Addr, dstAddr Addr, id uint16, seq uint16) error {
	if !srcAddr.IP.Is4() || !dstAddr.IP.Is4() {
		return ErrInvalidIP
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

	if Logger.IsDebug() {
		Logger.Msg("send echo4 request").IP("srcIP", srcAddr.IP).IP("dstIP", dstAddr.IP).Struct(ICMPEcho(p)).Write()
	}
	return h.icmp4SendPacket(srcAddr, dstAddr, p)
}

func (h *Session) icmp4SendPacket(srcAddr Addr, dstAddr Addr, p ICMP) (err error) {
	buf := EtherBufferPool.Get().(*[EthMaxSize]byte)
	defer EtherBufferPool.Put(buf)
	ether := Ether(buf[:])
	ether = EncodeEther(ether, syscall.ETH_P_IP, h.NICInfo.HostAddr4.MAC, dstAddr.MAC)
	ip4 := EncodeIP4(ether.Payload(), 50, srcAddr.IP, dstAddr.IP)
	if ip4, err = ip4.AppendPayload(p, syscall.IPPROTO_ICMP); err != nil {
		return err
	}
	if ether, err = ether.SetPayload(ip4); err != nil {
		return err
	}
	if _, err := h.Conn.WriteTo(ether, &dstAddr); err != nil {
		return err
	}
	return nil
}

// ICMP6SendEchoRequest transmit an icmp6 echo request and do not wait for response
func (h *Session) ICMP6SendEchoRequest(srcAddr Addr, dstAddr Addr, id uint16, seq uint16) error {
	if !srcAddr.IP.Is6() || !dstAddr.IP.Is6() {
		return ErrInvalidIP
	}
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

	if Logger.IsDebug() {
		Logger.Msg("send echo6 request").IP("srcIP", srcAddr.IP).IP("dstIP", dstAddr.IP).Struct(ICMPEcho(p)).Write()
	}
	return h.icmp6SendPacket(srcAddr, dstAddr, p)
}

func (h *Session) icmp6SendPacket(srcAddr Addr, dstAddr Addr, b []byte) error {
	buf := EtherBufferPool.Get().(*[EthMaxSize]byte)
	defer EtherBufferPool.Put(buf)
	ether := Ether(buf[:])

	// All Neighbor Discovery packets must use link-local addresses (FE80::/64)
	// and a hop limit of 255. Linux discards ND messages with hop limits different than 255.
	hopLimit := uint8(64)
	if dstAddr.IP.IsLinkLocalUnicast() || dstAddr.IP.IsLinkLocalMulticast() {
		hopLimit = 255
	}

	ether = EncodeEther(ether, syscall.ETH_P_IPV6, h.NICInfo.HostAddr4.MAC, dstAddr.MAC)
	ip6 := EncodeIP6(ether.Payload(), hopLimit, srcAddr.IP, dstAddr.IP)
	ip6, _ = ip6.AppendPayload(b, syscall.IPPROTO_ICMPV6)
	ether, _ = ether.SetPayload(ip6)

	// Calculate checksum of the pseudo header
	// The ICMPv6 checksum takes into account a pseudoheader of 40 bytes, which is a derivative of the real IPv6 header
	// which is composed as follows (in order):
	//   - 16 bytes for the source address
	//   - 16 bytes for the destination address
	//   - 4 bytes high endian payload length (the same value as in the IPv6 header)
	//   - 3 bytes zero
	//   - 1 byte nextheader (so, 58 decimal)
	psh := make([]byte, 40+len(b))
	copy(psh[0:16], ip6.Src().AsSlice())
	copy(psh[16:32], ip6.Dst().AsSlice())
	binary.BigEndian.PutUint32(psh[32:36], uint32(len(b)))
	psh[39] = 58
	copy(psh[40:], b)
	ICMP(ip6.Payload()).SetChecksum(Checksum(psh))

	if _, err := h.Conn.WriteTo(ether, &dstAddr); err != nil {
		fmt.Println("icmp6 : failed to write ", err)
		return err
	}

	return nil
}

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
func (h *Session) Ping6(srcAddr Addr, dstAddr Addr, timeout time.Duration) (err error) {
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

	if err = h.ICMP6SendEchoRequest(srcAddr, dstAddr, id, seq); err != nil {
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
		return ErrTimeout
	}
	return nil
}

// Ping send a ping request and wait for a reply
func (h *Session) Ping(dstAddr Addr, timeout time.Duration) (err error) {
	return h.ping(h.NICInfo.HostAddr4, dstAddr, timeout)
}

func (h *Session) ping(srcAddr Addr, dstAddr Addr, timeout time.Duration) (err error) {
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

	if err = h.ICMP4SendEchoRequest(srcAddr, dstAddr, id, seq); err != nil {
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
		return ErrTimeout
	}
	return nil
}

// ValidateDefaultRouter validates the default route is pointing to us by pinging
// client using home router IP as source IP. The reply will come to us
// when the default route on client is netfilter. If not, the ping
// reply will not be received.
//
// Note: the reply will also come to us if the client is undergoing
// an arp attack (hunt).
func (h *Session) ValidateDefaultRouter(addr Addr) error {
	// Test if client is online first
	// If client does not respond to echo, there is little we can test
	if err := h.Ping(addr, time.Second*2); err != nil {
		Logger.Msg("not responding to ping").Struct(addr).Write()
		return ErrTimeout
	}

	// first attempt
	err := h.ping(Addr{MAC: h.NICInfo.HostAddr4.MAC, IP: h.NICInfo.RouterAddr4.IP}, addr, time.Second*2)
	if err == nil {
		return nil
	}

	// second attempt
	err = h.ping(Addr{MAC: h.NICInfo.HostAddr4.MAC, IP: h.NICInfo.RouterAddr4.IP}, addr, time.Second*2)
	if err == nil {
		return nil
	}

	return ErrNotRedirected
}
