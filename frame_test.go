package packet

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHex(b []byte) []byte {
	b = bytes.ReplaceAll(b, []byte{' '}, nil)
	n, err := hex.Decode(b, b)
	if err != nil {
		panic(err)
	}
	return b[:n]
}

func TestSession_Parse(t *testing.T) {
	tests := []struct {
		name          string
		p             []byte
		wantFrame     Frame
		wantErr       bool
		wantPayloadID PayloadID
		wantHosts     int
	}{
		{name: "ether nil", p: nil, wantErr: true},
		{name: "ether too short", p: testEtherFrame[:10], wantErr: true},
		{name: "ether frame", p: testEtherFrame, wantErr: false, wantPayloadID: PayloadEther},
		{name: "ether rrcp", p: testEtherRRCP, wantErr: false, wantPayloadID: PayloadEther},
		{name: "ipv4 invalid", p: testIPv4Frame, wantErr: true, wantPayloadID: PayloadIP4, wantHosts: 0},
		{name: "icmp6 RA", p: testicmp6RourterSolicitation, wantErr: false, wantPayloadID: PayloadICMP6, wantHosts: 1},
		{name: "dhcp", p: mustHex(testDhcpDiscover), wantErr: false, wantPayloadID: PayloadDHCP4, wantHosts: 1}, // discover does not create host
		{name: "arp request", p: mustHex(testARPRequest), wantErr: false, wantPayloadID: PayloadARP, wantHosts: 1},
		{name: "arp reply", p: mustHex(testARPReply), wantErr: false, wantPayloadID: PayloadARP, wantHosts: 1},
		{name: "ssdp", p: mustHex(testSSDP), wantErr: false, wantPayloadID: PayloadSSDP, wantHosts: 1},
		{name: "mdns", p: mustHex(testMDNS), wantErr: false, wantPayloadID: PayloadMDNS, wantHosts: 1},
		{name: "dhcpv6", p: mustHex(testDHCPv6), wantErr: false, wantPayloadID: PayloadDHCP6, wantHosts: 2},
		{name: "dns", p: mustHex(testDNS), wantErr: false, wantPayloadID: PayloadDNS, wantHosts: 2},
		{name: "ntp", p: mustHex(testNTP), wantErr: false, wantPayloadID: PayloadNTP, wantHosts: 2},
		{name: "TCP", p: mustHex(testTCP), wantErr: false, wantPayloadID: PayloadTCP, wantHosts: 2},
		{name: "ICMPv4", p: mustHex(testICMPv4), wantErr: false, wantPayloadID: PayloadICMP4, wantHosts: 2},
		{name: "IGMP", p: mustHex(testIGMP), wantErr: false, wantPayloadID: PayloadIGMP, wantHosts: 2},
	}
	h := NewSession()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFrame, err := h.Parse(tt.p)
			if (err != nil) != tt.wantErr {
				t.Errorf("Session.Parse() %s error = %v, wantErr %v", tt.name, err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if gotFrame.Ether == nil {
				t.Errorf("Session.Parse() %s ether = %v, want %v", tt.name, gotFrame.Ether, tt.wantFrame)
			}
			if p := gotFrame.IP4(); p != nil && p.IsValid() != nil {
				t.Errorf("Session.Parse() %s invalid ip4 packet = %v", tt.name, p.IsValid())
			}
			if p := gotFrame.IP6(); p != nil && p.IsValid() != nil {
				t.Errorf("Session.Parse() %s invalid ip6 packet = %v", tt.name, p.IsValid())
			}
			if p := gotFrame.UDP(); p != nil && p.IsValid() != nil {
				t.Errorf("Session.Parse() %s invalid udp packet = %v", tt.name, p.IsValid())
			}
			if p := gotFrame.TCP(); p != nil && p.IsValid() != nil {
				t.Errorf("Session.Parse() %s invalid TCP packet = %v", tt.name, p.IsValid())
			}
			if gotFrame.PayloadID != tt.wantPayloadID {
				t.Errorf("Session.Parse() %s payloadID= %v, want %v", tt.name, gotFrame.PayloadID, tt.wantPayloadID)
			}
			if n := len(h.HostTable.Table); n != tt.wantHosts {
				t.Errorf("Session.Parse() %s hosts= %v, want %v", tt.name, n, tt.wantHosts)
			}
		})
	}
}

var testEtherFrame = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x55, 0x55, 0x55, 0x55, 0x55, 0x88, 0x99}

var testIPv4Frame = []byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x55, 0x55, 0x55, 0x55, 0x55, 0x08, 0x00, //ether frame
	0x45, 0x00, 0x00, 0x73, 0, 0, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8, 0, 0x01, 0xc0, 0xa8, 0, 0xc7}

var testEtherRRCP = []byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x55, 0x55, 0x55, 0x55, 0x55, 0x88, 0x99, //ether frame
	0x23, 0xd0, 0x44, 0xa2, 0x2e, 0xc3, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

var testicmp6RourterSolicitation = []byte{
	0x02, 0x42, 0xca, 0x78, 0x04, 0x50, 0xf8, 0xd0, 0x27, 0x3c, 0x9f, 0x86, 0x86, 0xdd, 0x60, 0x00, //  .B.x.P..'<....`.
	0x00, 0x00, 0x00, 0x08, 0x3a, 0xff, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfa, 0xd0, //  ....:...........
	0x27, 0xff, 0xfe, 0x3c, 0x9f, 0x86, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, //  '..<...........B
	0xca, 0xff, 0xfe, 0x78, 0x04, 0x50,
	0x85, 0x00, 0xb6, 0x46, 0x00, 0x00, 0x00, 0x00, // empty payload
}

var testDhcpDiscover = []byte(
	`ffff ffff ffff 8411 9e03 89c0 0800 4500` + //  ..............E.
		`0157 a4ff 0000 4011 d497 0000 0000 ffff` + //  .W....@.........
		`ffff 0044 0043 0143 8711 0101 0600 4eb1` + //  ...D.C.C......N.
		`32d6 0001 0000 0000 0000 0000 0000 0000` + //  2...............
		`0000 0000 0000 8411 9e03 89c0 0000 0000` + //  ................
		`0000 0000 0000 0000 0000 0000 0000 0000` + //  ................
		`0000 0000 0000 0000 0000 0000 0000 0000` + //  ................
		`0000 0000 0000 0000 0000 0000 0000 0000` + //  ................
		`0000 0000 0000 0000 0000 0000 0000 0000` + //  ................
		`0000 0000 0000 0000 0000 0000 0000 0000` + //  ................
		`0000 0000 0000 0000 0000 0000 0000 0000` + //  ................
		`0000 0000 0000 0000 0000 0000 0000 0000` + //  ................
		`0000 0000 0000 0000 0000 0000 0000 0000` + //  ................
		`0000 0000 0000 0000 0000 0000 0000 0000` + //  ................
		`0000 0000 0000 0000 0000 0000 0000 0000` + //  ................
		`0000 0000 0000 0000 0000 0000 0000 0000` + //  ................
		`0000 0000 0000 0000 0000 0000 0000 0000` + //  ................
		`0000 0000 0000 6382 5363 3501 033d 0701` + //  ......c.Sc5..=..
		`8411 9e03 89c0 3204 c0a8 0086 3902 05dc` + //  ......2.....9...
		`3c0c 6468 6370 6364 2d35 2e35 2e36 0c18` + //  <.dhcpcd-5.5.6..
		`616e 6472 6f69 642d 6438 6561 3030 3663` + //  android-d8ea006c
		`3964 3236 3930 6239 370a 0121 0306 0f1a` + //  9d2690b97..!....
		`1c33 3a3b ff`) //  .3:;.

var testARPRequest = []byte(
	// sudo tcpdump -en -vv -XX -t arp
	// dc:21:5c:3e:c9:f7 > ff:ff:ff:ff:ff:ff, ethertype ARP (0x0806), length 60: Ethernet (len 6), IPv4 (len 4), Request who-has 192.168.0.10 tell 192.168.0.102, length 46
	`ffff ffff ffff dc21 5c3e c9f7 0806 0001` + // .......!\>......
		`0800 0604 0001 dc21 5c3e c9f7 c0a8 0066 ` + //.......!\>.....f
		`0000 0000 0000 c0a8 000a 0000 0000 0000 ` + //................
		`0000 0000 0000 0000 0000 0000 `) //           ............

var testARPReply = []byte(
	// dc:21:5c:3e:c9:f7 > 02:42:15:e6:10:08, ethertype ARP (0x0806), length 60: Ethernet (len 6), IPv4 (len 4), Reply 192.168.0.102 is-at dc:21:5c:3e:c9:f7, length 46
	`0242 15e6 1008 dc21 5c3e c9f7 0806 0001` + //  .B.....!\>......
		`0800 0604 0002 dc21 5c3e c9f7 c0a8 0066` + //  .......!\>.....f
		`0242 15e6 1008 c0a8 0081 0000 0000 0000` + //  .B..............
		`0000 0000 0000 0000 0000 0000`)

var testSSDP = []byte(
	// cc:32:e5:0e:67:f4 > 01:00:5e:7f:ff:fa, ethertype IPv4 (0x0800), length 473: (tos 0x0, ttl 4, id 0, offset 0, flags [DF], proto UDP (17), length 459)
	// 192.168.1.1.55404 > 239.255.255.250.1900: [udp sum ok] UDP, length 431
	` 0100 5e7f fffa cc32 e50e 67f4 0800 4500` + //  ..^....2..g...E.
		` 01cb 0000 4000 0411 c37e c0a8 0101 efff` + //  ....@....~......
		` fffa d86c 076c 01b7 2897 4e4f 5449 4659` + //  ...l.l..(.NOTIFY
		` 202a 2048 5454 502f 312e 310d 0a48 4f53` + //  .*.HTTP/1.1..HOS
		` 543a 2032 3339 2e32 3535 2e32 3535 2e32` + //  T:.239.255.255.2
		` 3530 3a31 3930 300d 0a43 4143 4845 2d43` + //  50:1900..CACHE-C
		` 4f4e 5452 4f4c 3a20 6d61 782d 6167 653d` + //  ONTROL:.max-age=
		` 3330 300d 0a4c 4f43 4154 494f 4e3a 2068` + //  300..LOCATION:.h
		` 7474 703a 2f2f 3139 322e 3136 382e 312e` + //  ttp://192.168.1.
		` 313a 3139 3030 2f67 6174 6564 6573 632e` + //  1:1900/gatedesc.
		` 786d 6c0d 0a4f 5054 3a20 2268 7474 703a` + //  xml..OPT:."http:
		` 2f2f 7363 6865 6d61 732e 7570 6e70 2e6f` + //  //schemas.upnp.o
		` 7267 2f75 706e 702f 312f 302f 223b 206e` + //  rg/upnp/1/0/";.n
		` 733d 3031 0d0a 3031 2d4e 4c53 3a20 6162` + //  s=01..01-NLS:.ab
		` 6234 6633 3763 2d31 6464 312d 3131 6232` + //  b4f37c-1dd1-11b2
		` 2d38 3130 622d 6432 3136 6336 6336 3332` + //  -810b-d216c6c632
		` 3864 0d0a 4e54 3a20 7575 6964 3a39 6630` + //  8d..NT:.uuid:9f0
		` 3836 3562 332d 6635 6461 2d34 6164 352d` + //  865b3-f5da-4ad5-
		` 3835 6237 2d37 3430 3436 3337 6664 6633` + //  85b7-7404637fdf3
		` 370d 0a4e 5453 3a20 7373 6470 3a61 6c69` + //  7..NTS:.ssdp:ali
		` 7665 0d0a 5345 5256 4552 3a20 4c69 6e75` + //  ve..SERVER:.Linu
		` 782f 332e 342e 3131 2d72 7431 392c 2055` + //  x/3.4.11-rt19,.U
		` 506e 502f 312e 302c 2050 6f72 7461 626c` + //  PnP/1.0,.Portabl
		` 6520 5344 4b20 666f 7220 5550 6e50 2064` + //  e.SDK.for.UPnP.d
		` 6576 6963 6573 2f31 2e36 2e31 390d 0a58` + //  evices/1.6.19..X
		` 2d55 7365 722d 4167 656e 743a 2072 6564` + //  -User-Agent:.red
		` 736f 6e69 630d 0a55 534e 3a20 7575 6964` + //  sonic..USN:.uuid
		` 3a39 6630 3836 3562 332d 6635 6461 2d34` + //  :9f0865b3-f5da-4
		` 6164 352d 3835 6237 2d37 3430 3436 3337` + //  ad5-85b7-7404637
		` 6664 6633 370d 0a0d 0a                 `) //  fdf37....

var testMDNS = []byte(
	// b8:e9:37:52:4e:2c > 01:00:5e:00:00:fb, ethertype IPv4 (0x0800), length 108: (tos 0x0, ttl 255, id 0, offset 0, flags [DF], proto UDP (17), length 94)
	// 192.168.1.139.5353 > 224.0.0.251.5353: [udp sum ok] 0*- [0q] 1/0/0 _services._dns-sd._udp.local. PTR _sonos._tcp.local. (66)
	`0100 5e00 00fb b8e9 3752 4e2c 0800 4500` + //  ..^.....7RN,..E.
		`005e 0000 4000 ff11 d85f c0a8 018b e000` + //  .^..@...._......
		`00fb 14e9 14e9 004a 8852 0000 8400 0000` + //  .......J.R......
		`0001 0000 0000 095f 7365 7276 6963 6573` + //  ......._services
		`075f 646e 732d 7364 045f 7564 7005 6c6f` + //  ._dns-sd._udp.lo
		`6361 6c00 000c 0001 0000 1194 000e 065f` + //  cal............_
		`736f 6e6f 7304 5f74 6370 c023          `) //  sonos._tcp.#

var testDHCPv6 = []byte(
	// 7e:e8:94:42:29:aa > 33:33:00:01:00:02, ethertype IPv6 (0x86dd), length 108: (hlim 1, next-header UDP (17) payload length: 54) fe80::7ce8:94ff:fe42:29aa.546 > ff02::1:2.547: [udp sum ok] dhcp6 solicit (xid=52ec24 (client-ID hwaddr type 1 7ee8944229aa) (elapsed-time 65535) (option-request DNS-server) (IA_PD IAID:0 T1:0 T2:0))
	`3333 0001 0002 7ee8 9442 29aa 86dd 6000` + //  33....~..B)...`.
		`0000 0036 1101 fe80 0000 0000 0000 7ce8` + //  ...6..........|.
		`94ff fe42 29aa ff02 0000 0000 0000 0000` + //  ...B)...........
		`0000 0001 0002 0222 0223 0036 9938 0152` + //  .......".#.6.8.R
		`ec24 0001 000a 0003 0001 7ee8 9442 29aa` + //  .$........~..B).
		`0008 0002 ffff 0006 0002 0017 0019 000c` + //  ................
		`0000 0000 0000 0000 0000 0000          `) //  ............

var testDNS = []byte(
	// 02:42:ca:78:04:50 > cc:32:e5:0e:67:f4, ethertype IPv4 (0x0800), length 80: (tos 0x0, ttl 64, id 37973, offset 0, flags [DF], proto UDP (17), length 66)
	// 192.168.1.129.35791 > 8.8.8.8.53: [bad udp cksum 0xd278 -> 0x92a6!] 14045+ AAAA? api.blockthekids.com. (38)
	`cc32 e50e 67f4 0242 ca78 0450 0800 4500` + //  .2..g..B.x.P..E.
		`0042 9455 4000 4011 d41c c0a8 0181 0808` + //  .B.U@.@.........
		`0808 8bcf 0035 002e d278 36dd 0100 0001` + //  .....5...x6.....
		`0000 0000 0000 0361 7069 0c62 6c6f 636b` + //  .......api.block
		`7468 656b 6964 7303 636f 6d00 001c 0001`) //  thekids.com.....

var testNTP = []byte(
	// cc:32:e5:0e:67:f4 > 02:42:ca:78:04:50, ethertype IPv4 (0x0800), length 90: (tos 0x0, ttl 54, id 0, offset 0, flags [DF], proto UDP (17), length 76)
	// 220.158.215.21.123 > 192.168.1.129.41379: [udp sum ok] NTPv4, length 48
	// Server, Leap indicator:  (0), Stratum 2 (secondary reference), poll 10 (1024s), precision -23
	// Root Delay: 0.026351, Root dispersion: 0.005172, Reference-ID: 202.46.177.18
	//   Reference Timestamp:  3846423514.237310816 (2021/11/20 18:58:34)
	//   Originator Timestamp: 3062863826.389076998 (1997/01/21 19:30:26)
	//   Receive Timestamp:    3846423612.728495403 (2021/11/20 19:00:12)
	//   Transmit Timestamp:   3846423612.728540880 (2021/11/20 19:00:12)
	// Originator - Receive Timestamp:  +783559786.339418404
	// Originator - Transmit Timestamp: +783559786.339463882
	`0242 ca78 0450 cc32 e50e 67f4 0800 4500` + //  .B.x.P.2..g...E.
		`004c 0000 4000 3611 cec3 dc9e d715 c0a8` + //  .L..@.6.........
		`0181 007b a1a3 0038 8d41 2402 0ae9 0000` + //  ...{...8.A$.....
		`06bf 0000 0153 ca2e b112 e543 c3da 3cc0` + //  .....S.....C..<.
		`66d2 b68f 97d2 639a 8cd9 e543 c43c ba7e` + //  f.....c....C.<.~
		`acbe e543 c43c ba81 a7b9               `) //  ...C.<....

var testTCP = []byte(
	// 7e:e8:94:42:29:aa > 02:42:ca:78:04:50, ethertype IPv4 (0x0800), length 60: (tos 0x0, ttl 127, id 27794, offset 0, flags [DF], proto TCP (6), length 40)
	// 192.168.1.102.63599 > 192.168.1.129.22: Flags [.], cksum 0x8dd1 (correct), seq 2593, ack 4641068, win 517, length 0
	`0242 ca78 0450 7ee8 9442 29aa 0800 4500` + //  .B.x.P~..B)...E.
		`0028 6c92 4000 7f06 0b06 c0a8 0166 c0a8` + //  .(l.@........f..
		`0181 f86f 0016 4fc9 c1da 574d 3a4f 5010` + //  ...o..O...WM:OP.
		`0205 8dd1 0000 0000 0000 0000          `) //  ............

var testICMPv4 = []byte(
	// 02:42:ca:78:04:50 > aa:b5:3c:fd:69:93, ethertype IPv4 (0x0800), length 60: (tos 0xc0, ttl 50, id 0, offset 0, flags [none], proto ICMP (1), length 43)
	// 192.168.1.129 > 192.168.1.137: ICMP echo request, id 37286, seq 1, length 23
	`aab5 3cfd 6993 0242 ca78 0450 0800 45c0` + //  ..<.i..B.x.P..E.
		`002b 0000 0000 3201 03b8 c0a8 0181 c0a8` + //  .+....2.........
		`0189 0800 fca3 91a6 0001 4845 4c4c 4f2d` + //  ..........HELLO-
		`522d 552d 5448 4552 4500 0000          `) //  R-U-THERE...

var testIGMP = []byte(
	// cc:32:e5:0e:67:f4 > 01:00:5e:00:00:01, ethertype IPv4 (0x0800), length 60: (tos 0x0, ttl 1, id 0, offset 0, flags [DF], proto IGMP (2), length 36, options (RA))
	// 192.168.1.1 > 224.0.0.1: igmp query v3
	`0100 5e00 0001 cc32 e50e 67f4 0800 4600` + //  ..^....2..g...F.
		`0024 0000 4000 0102 4329 c0a8 0101 e000` + //  .$..@...C)......
		`0001 9404 0000 1164 ec1e 0000 0000 027d` + //  .......d.......}
		`0000 0000 0000 0000 0000 0000          `) //  ............
