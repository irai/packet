package dns

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/irai/packet"
)

func mustHex(b []byte) []byte {
	b = bytes.ReplaceAll(b, []byte{' '}, nil)
	n, err := hex.Decode(b, b)
	if err != nil {
		panic(err)
	}
	return b[:n]
}

func testSession() (*packet.Session, net.PacketConn) {
	hostIP := netip.MustParseAddr("192.168.0.129")
	homeLAN := netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 168, 0, 0}), 24)
	hostMAC := net.HardwareAddr{0x00, 0xff, 0x03, 0x04, 0x05, 0x01} // keep first byte zero for unicast mac
	routerMAC := net.HardwareAddr{0x00, 0x66, 0x66, 0x66, 0x66, 0x66}
	routerIP := netip.MustParseAddr("192.168.0.11")
	nicInfo := &packet.NICInfo{
		HomeLAN4:    homeLAN,
		HostAddr4:   packet.Addr{MAC: hostMAC, IP: hostIP},
		RouterAddr4: packet.Addr{MAC: routerMAC, IP: routerIP},
	}

	serverConn, clientConn := packet.TestNewBufferedConn()
	session, _ := packet.Config{Conn: serverConn, NICInfo: nicInfo}.NewSession("")
	return session, clientConn
}

func (p DNS) testDecode() (e DNSEntry, err error) {
	// question for doing name decoding.  We use a single reusable question to avoid
	// name decoding on a single object via multiple DecodeFromBytes calls
	// requiring constant allocation of small byte slices.
	var buffer []byte
	var answers []byte
	var question Question

	index := 12
	question, index, err = decodeQuestion(p, index, buffer)
	if err != nil {
		fmt.Printf("dns   : error decoding questions %s %s", err, p)
		return e, err
	}

	e = newDNSEntry()
	e.Name = string(question.Name)

	if _, _, err = e.decodeAnswers(p, index, answers); err != nil {
		fmt.Printf("dns   : error decoding answers %s %s", err, p)
		return e, err
	}

	return e, nil
}

/**
dig youtube.com  -  sudo tcpdump -en -v -XX -t port 53
34:e8:94:42:29:a9 > 02:42:15:e6:10:08, ethertype IPv4 (0x0800), length 98: (tos 0x0, ttl 63, id 0, offset 0, flags [DF], proto UDP (17), length 84)
    192.168.1.1.53 > 192.168.0.129.39768: 32691 1/0/1 youtube.com. A 142.250.66.238 (56)
*/

var testYouTubeCom = mustHex([]byte(
	`0242 15e6 1008 34e8 9442 29a9 0800 4500` + //  .B....4..B)...E.
		`0054 0000 4000 3f11 b8c6 c0a8 0101 c0a8` + //  .T..@.?.........
		`0081 0035 9b58 0040 3f81 7fb3 8180 0001` + //  ...5.X.@?.......
		`0001 0000 0001 0779 6f75 7475 6265 0363` + //  .......youtube.c
		`6f6d 0000 0100 01c0 0c00 0100 0100 0000` + //  om..............
		`d200 048e fa42 ee00 0029 1000 0000 0000` + //  .....B...)......
		`0000`))

/*
34:e8:94:42:29:a9 > 02:42:15:e6:10:08, ethertype IPv4 (0x0800), length 248: (tos 0x0, ttl 63, id 0, offset 0, flags [DF], proto UDP (17), length 234)
    192.168.1.1.53 > 192.168.0.129.60567: 36646 9/0/1
	www.youtube.com. CNAME youtube-ui.l.google.com.,
	youtube-ui.l.google.com. A 142.250.76.110,
	youtube-ui.l.google.com. A 142.250.204.14,
	youtube-ui.l.google.com. A 172.217.167.78,
	youtube-ui.l.google.com. A 142.250.66.238,
	youtube-ui.l.google.com. A 142.250.67.14,
	youtube-ui.l.google.com. A 142.250.71.78,
	youtube-ui.l.google.com. A 172.217.167.110,
	youtube-ui.l.google.com. A 142.250.66.206 (206)
*/
var testWwwYouTubeCom = mustHex([]byte(
	`0242 15e6 1008 34e8 9442 29a9 0800 4500` + //  .B....4..B)...E.
		`00ea 0000 4000 3f11 b830 c0a8 0101 c0a8` + //  ....@.?..0......
		`0081 0035 ec97 00d6 2019 8f26 8180 0001` + //  ...5.......&....
		`0009 0000 0001 0377 7777 0779 6f75 7475` + //  .......www.youtu
		`6265 0363 6f6d 0000 0100 01c0 0c00 0500` + //  be.com..........
		`0100 00dd 6700 160a 796f 7574 7562 652d` + //  ....g...youtube-
		`7569 016c 0667 6f6f 676c 65c0 18c0 2d00` + //  ui.l.google...-.
		`0100 0100 0000 ac00 048e fa4c 6ec0 2d00` + //  ...........Ln.-.
		`0100 0100 0000 ac00 048e facc 0ec0 2d00` + //  ..............-.
		`0100 0100 0000 ac00 04ac d9a7 4ec0 2d00` + //  ............N.-.
		`0100 0100 0000 ac00 048e fa42 eec0 2d00` + //  ...........B..-.
		`0100 0100 0000 ac00 048e fa43 0ec0 2d00` + //  ...........C..-.
		`0100 0100 0000 ac00 048e fa47 4ec0 2d00` + //  ...........GN.-.
		`0100 0100 0000 ac00 04ac d9a7 6ec0 2d00` + //  ............n.-.
		`0100 0100 0000 ac00 048e fa42 ce00 0029` + //  ...........B...)
		`1000 0000 0000 0000                    `)) //  ........

/**
; dig facebook.com - sudo tcpdump -X -t port 53
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 43228
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;facebook.com.                  IN      A

;; ANSWER SECTION:
facebook.com.           94      IN      A       157.240.8.35

;; Query time: 67 msec
;; SERVER: 192.168.1.1#53(192.168.1.1)
;; WHEN: Mon May 17 21:38:54 AEST 2021
;; MSG SIZE  rcvd: 57
*/

/*
dig www.facebook.com
34:e8:94:42:29:a9 > 02:42:15:e6:10:08, ethertype IPv4 (0x0800), length 132: (tos 0x0, ttl 63, id 0, offset 0, flags [DF], proto UDP (17), length 118)
    192.168.1.1.53 > 192.168.0.129.55588: 24213 2/0/1 www.facebook.com. CNAME star-mini.c10r.facebook.com., star-mini.c10r.facebook.com. A 157.240.8.35 (90)
*/
var testWwwFacebookComAnswer = mustHex([]byte(
	`0242 15e6 1008 34e8 9442 29a9 0800 4500` + //  .B....4..B)...E.
		`0076 0000 4000 3f11 b8a4 c0a8 0101 c0a8` + //  .v..@.?.........
		`0081 0035 d924 0062 fa53 5e95 8180 0001` + //  ...5.$.b.S^.....
		`0002 0000 0001 0377 7777 0866 6163 6562` + //  .......www.faceb
		`6f6f 6b03 636f 6d00 0001 0001 c00c 0005` + //  ook.com.........
		`0001 0000 05b5 0011 0973 7461 722d 6d69` + //  .........star-mi
		`6e69 0463 3130 72c0 10c0 2e00 0100 0100` + //  ni.c10r.........
		`0000 3100 049d f008 2300 0029 1000 0000` + //  ..1.....#..)....
		`0000 0000                              `)) //  ....

/*
; dig www.blockthekids.com - sudo tcpdump -X -t port 53
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 51225
;; flags: qr rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;www.blockthekids.com.          IN      A

;; ANSWER SECTION:
www.blockthekids.com.   14400   IN      CNAME   www245.wixdns.net.
www245.wixdns.net.      600     IN      CNAME   balancer.wixdns.net.
balancer.wixdns.net.    294     IN      CNAME   c098a3f6-balancer.wixdns.net.
c098a3f6-balancer.wixdns.net. 294 IN    CNAME   td-balancer-ause1-67-249.wixdns.net.
td-balancer-ause1-67-249.wixdns.net. 242 IN A   35.244.67.249

;; Query time: 439 msec
;; SERVER: 192.168.1.1#53(192.168.1.1)
;; WHEN: Tue May 18 10:38:12 AEST 2021
;; MSG SIZE  rcvd: 190

		34:e8:94:42:29:a9 > 02:42:15:e6:10:08, ethertype IPv4 (0x0800), length 232: (tos 0x0, ttl 63, id 0, offset 0, flags [DF], proto UDP (17), length 218)
    192.168.1.1.53 > 192.168.0.129.46239: 24076 5/0/1
	www.blockthekids.com. CNAME www245.wixdns.net.,
	www245.wixdns.net. CNAME balancer.wixdns.net.,
	balancer.wixdns.net. CNAME c098a3f6-balancer.wixdns.net.,
	c098a3f6-balancer.wixdns.net. CNAME td-balancer-ause1-67-249.wixdns.net.,
	td-balancer-ause1-67-249.wixdns.net. A 35.244.67.249 (190)
*/
var testWwwBlockTheKidsCom = mustHex([]byte(
	`0242 15e6 1008 34e8 9442 29a9 0800 4500` + //  .B....4..B)...E.
		`00da 0000 4000 3f11 b840 c0a8 0101 c0a8` + //  ....@.?..@......
		`0081 0035 b49f 00c6 c0c9 5e0c 8180 0001` + //  ...5......^.....
		`0005 0000 0001 0377 7777 0c62 6c6f 636b` + //  .......www.block
		`7468 656b 6964 7303 636f 6d00 0001 0001` + //  thekids.com.....
		`c00c 0005 0001 0000 3840 0013 0677 7777` + //  ........8@...www
		`3234 3506 7769 7864 6e73 036e 6574 00c0` + //  245.wixdns.net..
		`3200 0500 0100 0001 4400 0b08 6261 6c61` + //  2.......D...bala
		`6e63 6572 c039 c051 0005 0001 0000 0078` + //  ncer.9.Q.......x
		`0014 1163 3039 3861 3366 362d 6261 6c61` + //  ...c098a3f6-bala
		`6e63 6572 c039 c068 0005 0001 0000 0078` + //  ncer.9.h.......x
		`001b 1874 642d 6261 6c61 6e63 6572 2d61` + //  ...td-balancer-a
		`7573 6531 2d36 372d 3234 39c0 39c0 8800` + //  use1-67-249.9...
		`0100 0100 0003 3400 0423 f443 f900 0029` + //  ......4..#.C...)
		`1000 0000 0000 0000                    `)) //  ........

/***
; <<>> DiG 9.16.1-Ubuntu <<>> -x 17.253.67.203
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 50185
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;203.67.253.17.in-addr.arpa.    IN      PTR

;; ANSWER SECTION:
203.67.253.17.in-addr.arpa. 14400 IN    PTR     ausyd2-vip-bx-003.aaplimg.com.

;; Query time: 7 msec
;; SERVER: 192.168.1.1#53(192.168.1.1)
;; WHEN: Sat May 22 08:06:46 AEST 2021
;; MSG SIZE  rcvd: 98
*/
// IP 192.168.1.1.domain > netfilter.33201: 50185 1/0/1 PTR ausyd2-vip-bx-003.aaplimg.com. (98)
var wwwPTRResponse = []byte{
	0x02, 0x42, 0xca, 0x78, 0x04, 0x50, 0x7e, 0xe8, 0x94, 0x42, 0x29, 0xaa, 0x08, 0x00, // ethernet
	0x45, 0x00, 0x00, 0x7e, 0x00, 0x00, 0x40, 0x00, 0x3f, 0x11, 0xb8, 0x9c, 0xc0, 0xa8, 0x01, 0x01, // E..~..@.?.......
	0xc0, 0xa8, 0x00, 0x81, 0x00, 0x35, 0x81, 0xb1, 0x00, 0x6a, 0x07, 0x8d, 0xc4, 0x09, 0x81, 0x80, // .....5...j......
	0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x03, 0x32, 0x30, 0x33, 0x02, 0x36, 0x37, 0x03, // .........203.67.
	0x32, 0x35, 0x33, 0x02, 0x31, 0x37, 0x07, 0x69, 0x6e, 0x2d, 0x61, 0x64, 0x64, 0x72, 0x04, 0x61, // 253.17.in-addr.a
	0x72, 0x70, 0x61, 0x00, 0x00, 0x0c, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, // rpa.............
	0x38, 0x40, 0x00, 0x1f, 0x11, 0x61, 0x75, 0x73, 0x79, 0x64, 0x32, 0x2d, 0x76, 0x69, 0x70, 0x2d, // 8@...ausyd2-vip-
	0x62, 0x78, 0x2d, 0x30, 0x30, 0x33, 0x07, 0x61, 0x61, 0x70, 0x6c, 0x69, 0x6d, 0x67, 0x03, 0x63, // bx-003.aaplimg.c
	0x6f, 0x6d, 0x00, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // om...)........
}

/**
; <<>> DiG 9.16.1-Ubuntu <<>> twitter.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 36571
;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 10, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;twitter.com.                   IN      A

;; ANSWER SECTION:
twitter.com.            1081    IN      A       104.244.42.1
twitter.com.            1081    IN      A       104.244.42.65

;; AUTHORITY SECTION:
twitter.com.            9525    IN      NS      ns2.p34.dynect.net.
twitter.com.            9525    IN      NS      d01-02.ns.twtrdns.net.
twitter.com.            9525    IN      NS      b.r06.twtrdns.net.
twitter.com.            9525    IN      NS      ns4.p34.dynect.net.
twitter.com.            9525    IN      NS      c.r06.twtrdns.net.
twitter.com.            9525    IN      NS      a.r06.twtrdns.net.
twitter.com.            9525    IN      NS      ns1.p34.dynect.net.
twitter.com.            9525    IN      NS      ns3.p34.dynect.net.
twitter.com.            9525    IN      NS      d.r06.twtrdns.net.
twitter.com.            9525    IN      NS      d01-01.ns.twtrdns.net.

;; Query time: 11 msec
;; SERVER: 192.168.1.1#53(192.168.1.1)
;; WHEN: Thu Jan 27 22:08:45 AEDT 2022

34:e8:94:42:29:a9 > 02:42:15:e6:10:08, ethertype IPv4 (0x0800), length 321: (tos 0x0, ttl 63, id 0, offset 0, flags [DF], proto UDP (17), length 307)
    192.168.1.1.53 > 192.168.0.129.58480: 36571 2/10/1 twitter.com. A 104.244.42.1, twitter.com. A 104.244.42.65 (279)
*/
var testTwitterCom = mustHex([]byte(
	`0242 15e6 1008 34e8 9442 29a9 0800 4500` + //  .B....4..B)...E.
		`0133 0000 4000 3f11 b7e7 c0a8 0101 c0a8` + //  .3..@.?.........
		`0081 0035 e470 011f f091 8edb 8180 0001` + //  ...5.p..........
		`0002 000a 0001 0774 7769 7474 6572 0363` + //  .......twitter.c
		`6f6d 0000 0100 01c0 0c00 0100 0100 0004` + //  om..............
		`3900 0468 f42a 01c0 0c00 0100 0100 0004` + //  9..h.*..........
		`3900 0468 f42a 41c0 0c00 0200 0100 0025` + //  9..h.*A........%
		`3500 1403 6e73 3203 7033 3406 6479 6e65` + //  5...ns2.p34.dyne
		`6374 036e 6574 00c0 0c00 0200 0100 0025` + //  ct.net.........%
		`3500 1406 6430 312d 3032 026e 7307 7477` + //  5...d01-02.ns.tw
		`7472 646e 73c0 58c0 0c00 0200 0100 0025` + //  trdns.X........%
		`3500 0801 6203 7230 36c0 73c0 0c00 0200` + //  5...b.r06.s.....
		`0100 0025 3500 0603 6e73 34c0 4dc0 0c00` + //  ...%5...ns4.M...
		`0200 0100 0025 3500 0401 63c0 8bc0 0c00` + //  .....%5...c.....
		`0200 0100 0025 3500 0401 61c0 8bc0 0c00` + //  .....%5...a.....
		`0200 0100 0025 3500 0603 6e73 31c0 4dc0` + //  .....%5...ns1.M.
		`0c00 0200 0100 0025 3500 0603 6e73 33c0` + //  .......%5...ns3.
		`4dc0 0c00 0200 0100 0025 3500 0401 64c0` + //  M........%5...d.
		`8bc0 0c00 0200 0100 0025 3500 0906 6430` + //  .........%5...d0
		`312d 3031 c070 0000 2910 0000 0000 0000` + //  1-01.p..).......
		`00`)) //

/**
; <<>> DiG 9.16.1-Ubuntu <<>> www.snapchat.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 62194
;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;www.snapchat.com.              IN      A

;; ANSWER SECTION:
www.snapchat.com.       3129    IN      CNAME   ghs.googlehosted.com.
ghs.googlehosted.com.   263     IN      A       172.217.167.83

;; Query time: 15 msec
;; SERVER: 192.168.1.1#53(192.168.1.1)
;; WHEN: Thu Jan 27 22:33:35 AEDT 2022
;; MSG SIZE  rcvd: 92
		34:e8:94:42:29:a9 > 02:42:15:e6:10:08, ethertype IPv4 (0x0800), length 134: (tos 0x0, ttl 63, id 0, offset 0, flags [DF], proto UDP (17), length 120)
    192.168.1.1.53 > 192.168.0.129.33415: 62194 2/0/1 www.snapchat.com. CNAME ghs.googlehosted.com., ghs.googlehosted.com. A 172.217.167.83 (92)
        0x0000:  0242 15e6 1008 34e8 9442 29a9 0800 4500  .B....4..B)...E.
        0x0010:  0078 0000 4000 3f11 b8a2 c0a8 0101 c0a8  .x..@.?.........
        0x0020:  0081 0035 8287 0064 1a66 f2f2 8180 0001  ...5...d.f......
        0x0030:  0002 0000 0001 0377 7777 0873 6e61 7063  .......www.snapc
        0x0040:  6861 7403 636f 6d00 0001 0001 c00c 0005  hat.com.........
        0x0050:  0001 0000 0c39 0013 0367 6873 0c67 6f6f  .....9...ghs.goo
        0x0060:  676c 6568 6f73 7465 64c0 19c0 2e00 0100  glehosted.......
        0x0070:  0100 0001 0700 04ac d9a7 5300 0029 1000  ..........S..)..
        0x0080:  0000 0000 0000                           ......
*/

/*
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 41203
;; flags: qr rd ra; QUERY: 1, ANSWER: 4, AUTHORITY: 4, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;snapchat.com.                  IN      A

;; ANSWER SECTION:
snapchat.com.           9       IN      A       216.239.34.21
snapchat.com.           9       IN      A       216.239.32.21
snapchat.com.           9       IN      A       216.239.36.21
snapchat.com.           9       IN      A       216.239.38.21

;; AUTHORITY SECTION:
snapchat.com.           73513   IN      NS      ns-1468.awsdns-55.org.
snapchat.com.           73513   IN      NS      ns-1892.awsdns-44.co.uk.
snapchat.com.           73513   IN      NS      ns-220.awsdns-27.com.
snapchat.com.           73513   IN      NS      ns-530.awsdns-02.net.

;; Query time: 15 msec
;; SERVER: 192.168.1.1#53(192.168.1.1)
;; WHEN: Thu Jan 27 22:36:36 AEDT 2022
;; MSG SIZE  rcvd: 242
34:e8:94:42:29:a9 > 02:42:15:e6:10:08, ethertype IPv4 (0x0800), length 284: (tos 0x0, ttl 63, id 0, offset 0, flags [DF], proto UDP (17), length 270)
    192.168.1.1.53 > 192.168.0.129.38189: 41203 4/4/1 snapchat.com. A 216.239.34.21, snapchat.com. A 216.239.32.21, snapchat.com. A 216.239.36.21, snapchat.com. A 216.239.38.21 (242)
        0x0000:  0242 15e6 1008 34e8 9442 29a9 0800 4500  .B....4..B)...E.
        0x0010:  010e 0000 4000 3f11 b80c c0a8 0101 c0a8  ....@.?.........
        0x0020:  0081 0035 952d 00fa 12d7 a0f3 8180 0001  ...5.-..........
        0x0030:  0004 0004 0001 0873 6e61 7063 6861 7403  .......snapchat.
        0x0040:  636f 6d00 0001 0001 c00c 0001 0001 0000  com.............
        0x0050:  0009 0004 d8ef 2215 c00c 0001 0001 0000  ......".........
        0x0060:  0009 0004 d8ef 2015 c00c 0001 0001 0000  ................
        0x0070:  0009 0004 d8ef 2415 c00c 0001 0001 0000  ......$.........
        0x0080:  0009 0004 d8ef 2615 c00c 0002 0001 0001  ......&.........
        0x0090:  1f29 0017 076e 732d 3134 3638 0961 7773  .)...ns-1468.aws
        0x00a0:  646e 732d 3535 036f 7267 00c0 0c00 0200  dns-55.org......
        0x00b0:  0100 011f 2900 1907 6e73 2d31 3839 3209  ....)...ns-1892.
        0x00c0:  6177 7364 6e73 2d34 3402 636f 0275 6b00  awsdns-44.co.uk.
        0x00d0:  c00c 0002 0001 0001 1f29 0013 066e 732d  .........)...ns-
        0x00e0:  3232 3009 6177 7364 6e73 2d32 37c0 15c0  220.awsdns-27...
        0x00f0:  0c00 0200 0100 011f 2900 1606 6e73 2d35  ........)...ns-5
        0x0100:  3330 0961 7773 646e 732d 3032 036e 6574  30.awsdns-02.net
        0x0110:  0000 0029 1000 0000 0000 0000            ...)........
*/

func TestDNSHandler_ProcessDNS(t *testing.T) {

	tests := []struct {
		name        string
		packet      []byte
		wantName    string
		wantIP4     netip.Addr
		wantIP4Name string
		wantPTRName string
		wantPTRIP4  netip.Addr
		wantErr     bool
	}{
		{name: "www.facebook.com", wantErr: false, packet: testWwwFacebookComAnswer, wantName: "www.facebook.com", wantIP4: netip.AddrFrom4([4]byte{157, 240, 8, 35}), wantIP4Name: "star-mini.c10r.facebook.com"},
		{name: "www.youtube.com", wantErr: false, packet: testWwwYouTubeCom, wantName: "www.youtube.com", wantIP4: netip.AddrFrom4([4]byte{142, 250, 66, 206}), wantIP4Name: "youtube-ui.l.google.com"},
		{name: "youtube.com", wantErr: false, packet: testYouTubeCom, wantName: "youtube.com", wantIP4: netip.AddrFrom4([4]byte{142, 250, 66, 238}), wantIP4Name: "youtube.com"},
		{name: "www.blockthekids.com", wantErr: false, packet: testWwwBlockTheKidsCom, wantName: "www.blockthekids.com", wantIP4: netip.AddrFrom4([4]byte{35, 244, 67, 249}), wantIP4Name: "td-balancer-ause1-67-249.wixdns.net"},
		{name: "ptr", wantErr: false, packet: wwwPTRResponse, wantName: "203.67.253.17.in-addr.arpa", wantPTRIP4: netip.AddrFrom4([4]byte{17, 253, 67, 203}), wantPTRName: "ausyd2-vip-bx-003.aaplimg.com"},
	}

	session, _ := testSession()
	defer session.Close()
	dnsHandler, err := New(session)
	if err != nil {
		t.Fatal("invalid packet", err)
	}
	Debug = true

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame, err := session.Parse(tt.packet)
			if err != nil {
				t.Fatal("invalid packet", err)
			}
			gotE, err := dnsHandler.ProcessDNS(frame)
			if (err != nil) != tt.wantErr {
				t.Errorf("DNSHandler.ProcessDNS() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotE.Name != tt.wantName {
				t.Errorf("DNSHandler.ProcessDNS() invalid name= %+v, want=%v", gotE, tt.wantName)
			}
			if tt.wantIP4.IsValid() {
				r, ok := gotE.IP4Records[tt.wantIP4]
				if !ok || r.Name != tt.wantIP4Name {
					t.Errorf("invalid record %+v ", r)
				}
			}
			if tt.wantPTRName != "" {
				r, ok := gotE.PTRRecords[tt.wantPTRName]
				if !ok || r.IP != tt.wantPTRIP4 {
					t.Errorf("invalid record %+v ", r)
				}

			}
		})
	}

	if n := len(dnsHandler.DNSTable); n != 5 {
		t.Fatalf("invalid dns table len=%v want=5 ", n)
	}
}

func TestDNS_reverseDNS(t *testing.T) {
	session, clientConn := testSession()
	defer session.Close()
	go packet.TestReadAndDiscardLoop(clientConn) // MUST read the out conn to avoid blocking the server

	dnsHandler, _ := New(session)
	Debug = true

	if err := ReverseDNS(netip.AddrFrom4([4]byte{172, 217, 167, 118})); err != nil {
		t.Fatal(err)
	}
	// =13.76.219.18
	if found := dnsHandler.DNSExist(netip.AddrFrom4([4]byte{13, 76, 219, 18})); found {
		t.Fatal("invalid entry")
	}

	dnsHandler.DNSLookupPTR(netip.AddrFrom4([4]byte{13, 76, 219, 18}))

	if found := dnsHandler.DNSExist(netip.AddrFrom4([4]byte{13, 76, 219, 18})); !found {
		dnsHandler.PrintDNSTable()
		t.Fatal("invalid entry")
	}

	dnsHandler.DNSLookupPTR(netip.AddrFrom4([4]byte{13, 76, 219, 18}))

	entry, found := dnsHandler.DNSTable["ptrentryname"]
	if !found || len(entry.IP4Records) != 1 {
		dnsHandler.PrintDNSTable()
		t.Fatal("invalid entry")
	}

}

// Benchmark_DNSConcurrentAccess test concurrent access performance
// Benchmark_DNSConcurrentAccess-8   	  114400	     10260 ns/op	    6267 B/op	      52 allocs/op
func Benchmark_DNSConcurrentAccess(b *testing.B) {
	session, clientConn := testSession()
	defer session.Close()
	go packet.TestReadAndDiscardLoop(clientConn) // MUST read the out conn to avoid blocking the server

	dnsHandler, _ := New(session)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			for _, v := range [][]byte{testWwwYouTubeCom, testWwwFacebookComAnswer, testWwwBlockTheKidsCom, testWwwFacebookComAnswer} {
				frame, err := session.Parse(v)
				if err != nil {
					b.Errorf("invalid process packet bltk %s", err)
				}

				r, err := dnsHandler.ProcessDNS(frame)
				if err != nil {
					b.Fatalf("invalid process packet bltk %+v %s\n", r, err)
				}
			}
			e := dnsHandler.DNSFind("www.blockthekids.com")
			if e.Name != "www.blockthekids.com" {
				b.Fatal("invalid blockthekids name", e)
			}
			e = dnsHandler.DNSFind("www.youtube.com")
			if e.Name != "www.youtube.com" {
				b.Fatal("invalid youtube name", e)
			}
			e = dnsHandler.DNSFind("www.facebook.com")
			if e.Name != "www.facebook.com" {
				dnsHandler.PrintDNSTable()
				b.Fatal("invalid facebook name", e)
			}
		}
	})

	/**
	b.Run("facebook", func(b *testing.B) {
	})

	b.RunParallel("youtube", func(b *testing.B) {
	})
	**/
}

func BenchmarkEncode(b *testing.B) {
	session, _ := testSession()
	defer session.Close()

	frame, _ := session.Parse(testWwwYouTubeCom)

	b.ReportAllocs()

	b.Run("decodeName with buffer", func(b *testing.B) {
		buffer := make([]byte, 0, 64)
		for i := 0; i < b.N; i++ {
			dnsFrame := DNS(frame.Payload())
			question, index, err := decodeQuestion(dnsFrame, 12, buffer)
			if err != nil || question.Name == nil || index == -1 {
				b.Fatal("Message.Pack() =", err, question, index)
			}
			e := newDNSEntry()
			if _, _, err = e.decodeAnswers(dnsFrame, index, buffer); err != nil {
				b.Fatal("Message.Pack() decode error =", err)
			}
		}
	})
	b.Run("decodeName empty buffer", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var buffer []byte
			dnsFrame := DNS(frame.Payload())
			question, index, err := decodeQuestion(dnsFrame, 12, buffer)
			if err != nil || question.Name == nil || index == -1 {
				b.Fatal("Message.Pack() =", err, question, index)
			}
			e := newDNSEntry()
			if _, _, err = e.decodeAnswers(dnsFrame, index, buffer); err != nil {
				b.Fatal("Message.Pack() decode error =", err)
			}
		}
	})
}
