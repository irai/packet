package dns

import (
	"fmt"
	"net"
	"testing"

	"github.com/irai/packet"
	"inet.af/netaddr"
)

func testSession() *packet.Session {
	// fake nicinfo
	hostMAC := net.HardwareAddr{0x00, 0xff, 0x03, 0x04, 0x05, 0x01} // keep first byte zero for unicast mac
	routerMAC := net.HardwareAddr{0x00, 0x66, 0x66, 0x66, 0x66, 0x66}
	hostIP := net.ParseIP("192.168.0.129").To4()
	homeLAN := net.IPNet{IP: net.IPv4(192, 168, 0, 0), Mask: net.IPv4Mask(255, 255, 255, 0)}
	routerIP := net.ParseIP("192.168.0.11").To4()
	nicInfo := &packet.NICInfo{
		HomeLAN4:    homeLAN,
		HostAddr4:   packet.Addr{MAC: hostMAC, IP: hostIP},
		RouterAddr4: packet.Addr{MAC: routerMAC, IP: routerIP},
	}

	// TODO: fix this to discard writes like ioutil.Discard
	conn, _ := net.ListenPacket("udp4", "127.0.0.1:0")

	session, _ := packet.Config{Conn: conn, NICInfo: nicInfo}.NewSession("")
	return session
}

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

var wwwFacebookComAnswer = []byte{
	0x45, 0x00, 0x00, 0x55, 0x00, 0x00, 0x40, 0x00, 0x3f, 0x11, 0xb8, 0xc5, 0xc0, 0xa8, 0x01, 0x01, // E..U..@.?.......
	0xc0, 0xa8, 0x00, 0x81, 0x00, 0x35, 0xa5, 0x70, 0x00, 0x41, 0xfb, 0x2b, 0x50, 0x15, 0x81, 0x80, // .....5.p.A.+P...
	0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x66, 0x61, 0x63, 0x65, 0x62, 0x6f, 0x6f, // .........faceboo
	0x6b, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, // k.com...........
	0x00, 0x00, 0x00, 0xe8, 0x00, 0x04, 0x9d, 0xf0, 0x08, 0x23, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, // .........#..)...
	0x00, 0x00, 0x00, 0x00, 0x00,
}

func TestDNS_DecodeFacebook(t *testing.T) {

	ip := packet.IP4(wwwFacebookComAnswer)
	fmt.Println("ip", ip)
	udp := packet.UDP(ip.Payload())
	fmt.Println("udp", udp)
	p := DNS(udp.Payload())
	fmt.Println("dns", p)
	if p.IsValid() != nil {
		t.Fatal("invalid dns packet")
	}

	entry, err := p.decode()
	if err != nil {
		t.Fatal("cannot decode", err)
	}
	r, ok := entry.IP4Records[netaddr.IPv4(157, 240, 8, 35)]
	if !ok || r.Name != "facebook.com" {
		t.Fatalf("invalid packet %+v ", r)
	}
}

/**
;; dig www.youtube.com - sudo tcpdump -X -t port 53
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 8855
;; flags: qr rd ra; QUERY: 1, ANSWER: 10, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;www.youtube.com.               IN      A

;; ANSWER SECTION:
www.youtube.com.        11843   IN      CNAME   youtube-ui.l.google.com.
youtube-ui.l.google.com. 7      IN      A       142.250.66.238
youtube-ui.l.google.com. 7      IN      A       142.250.67.14
youtube-ui.l.google.com. 7      IN      A       142.250.71.78
youtube-ui.l.google.com. 7      IN      A       142.250.76.110
youtube-ui.l.google.com. 7      IN      A       142.250.204.14
youtube-ui.l.google.com. 7      IN      A       172.217.167.78
youtube-ui.l.google.com. 7      IN      A       172.217.167.110
youtube-ui.l.google.com. 7      IN      A       142.250.66.174
youtube-ui.l.google.com. 7      IN      A       142.250.66.206

;; Query time: 11 msec
;; SERVER: 192.168.1.1#53(192.168.1.1)
;; WHEN: Mon May 17 23:25:40 AEST 2021
;; MSG SIZE  rcvd: 222
*/
var wwwYouTubeComResponse = []byte{
	0x45, 0x00, 0x00, 0xfa, 0x00, 0x00, 0x40, 0x00, 0x3f, 0x11, 0xb8, 0x20, 0xc0, 0xa8, 0x01, 0x01, // E.....@.?.......
	0xc0, 0xa8, 0x00, 0x81, 0x00, 0x35, 0xd0, 0x01, 0x00, 0xe6, 0x67, 0x08, 0xe0, 0xc6, 0x81, 0x80, // .....5....g.....
	0x00, 0x01, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x01, 0x03, 0x77, 0x77, 0x77, 0x07, 0x79, 0x6f, 0x75, // .........www.you
	0x74, 0x75, 0x62, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, // tube.com........
	0x05, 0x00, 0x01, 0x00, 0x00, 0x30, 0x09, 0x00, 0x16, 0x0a, 0x79, 0x6f, 0x75, 0x74, 0x75, 0x62, // .....0....youtub
	0x65, 0x2d, 0x75, 0x69, 0x01, 0x6c, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0xc0, 0x18, 0xc0, // e-ui.l.google...
	0x2d, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xb6, 0x00, 0x04, 0x8e, 0xfa, 0x42, 0xce, 0xc0, // -............B..
	0x2d, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xb6, 0x00, 0x04, 0x8e, 0xfa, 0x42, 0xee, 0xc0, // -............B..
	0x2d, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xb6, 0x00, 0x04, 0x8e, 0xfa, 0x43, 0x0e, 0xc0, // -............C..
	0x2d, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xb6, 0x00, 0x04, 0x8e, 0xfa, 0x47, 0x4e, 0xc0, // -............GN.
	0x2d, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xb6, 0x00, 0x04, 0x8e, 0xfa, 0x4c, 0x6e, 0xc0, // -............Ln.
	0x2d, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xb6, 0x00, 0x04, 0x8e, 0xfa, 0xcc, 0x0e, 0xc0, // -...............
	0x2d, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xb6, 0x00, 0x04, 0xac, 0xd9, 0xa7, 0x4e, 0xc0, // -.............N.
	0x2d, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xb6, 0x00, 0x04, 0xac, 0xd9, 0xa7, 0x6e, 0xc0, // -.............n.
	0x2d, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xb6, 0x00, 0x04, 0x8e, 0xfa, 0x42, 0xae, 0x00, // -............B..
	0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // .)........
}

func TestDNS_DecodeYouTube(t *testing.T) {

	ip := packet.IP4(wwwYouTubeComResponse)
	fmt.Println("ip", ip)
	udp := packet.UDP(ip.Payload())
	fmt.Println("udp", udp)
	p := DNS(udp.Payload())
	fmt.Println("dns", p)
	if p.IsValid() != nil {
		t.Fatal("invalid dns packet")
	}

	entry, err := p.decode()
	if err != nil {
		t.Fatal("cannot decode", err)
	}
	r, ok := entry.IP4Records[netaddr.IPv4(142, 250, 66, 206)]
	if len(entry.IP4Records) != 9 || !ok || r.Name != "youtube-ui.l.google.com" {
		t.Fatalf("invalid packet %+v ", r)
	}
}

/**
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
*/

var wwwBlockthekidsComResponse = []byte{
	0x45, 0x00, 0x00, 0xda, 0x00, 0x00, 0x40, 0x00, 0x3f, 0x11, 0xb8, 0x40, 0xc0, 0xa8, 0x01, 0x01, // E.....@.?..@....
	0xc0, 0xa8, 0x00, 0x81, 0x00, 0x35, 0x92, 0x23, 0x00, 0xc6, 0xa5, 0xdd, 0xc8, 0x19, 0x81, 0x80, // .....5.#........
	0x00, 0x01, 0x00, 0x05, 0x00, 0x00, 0x00, 0x01, 0x03, 0x77, 0x77, 0x77, 0x0c, 0x62, 0x6c, 0x6f, // .........www.blo
	0x63, 0x6b, 0x74, 0x68, 0x65, 0x6b, 0x69, 0x64, 0x73, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, // ckthekids.com...
	0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x38, 0x40, 0x00, 0x13, 0x06, 0x77, // ..........8@...w
	0x77, 0x77, 0x32, 0x34, 0x35, 0x06, 0x77, 0x69, 0x78, 0x64, 0x6e, 0x73, 0x03, 0x6e, 0x65, 0x74, // ww245.wixdns.net
	0x00, 0xc0, 0x32, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x02, 0x58, 0x00, 0x0b, 0x08, 0x62, 0x61, // ..2.......X...ba
	0x6c, 0x61, 0x6e, 0x63, 0x65, 0x72, 0xc0, 0x39, 0xc0, 0x51, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, // lancer.9.Q......
	0x01, 0x26, 0x00, 0x14, 0x11, 0x63, 0x30, 0x39, 0x38, 0x61, 0x33, 0x66, 0x36, 0x2d, 0x62, 0x61, // .&...c098a3f6-ba
	0x6c, 0x61, 0x6e, 0x63, 0x65, 0x72, 0xc0, 0x39, 0xc0, 0x68, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, // lancer.9.h......
	0x01, 0x26, 0x00, 0x1b, 0x18, 0x74, 0x64, 0x2d, 0x62, 0x61, 0x6c, 0x61, 0x6e, 0x63, 0x65, 0x72, // .&...td-balancer
	0x2d, 0x61, 0x75, 0x73, 0x65, 0x31, 0x2d, 0x36, 0x37, 0x2d, 0x32, 0x34, 0x39, 0xc0, 0x39, 0xc0, // -ause1-67-249.9.
	0x88, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xf2, 0x00, 0x04, 0x23, 0xf4, 0x43, 0xf9, 0x00, // ...........#.C..
	0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

func TestDNS_DecodeBlockTheKids(t *testing.T) {

	ip := packet.IP4(wwwBlockthekidsComResponse)
	udp := packet.UDP(ip.Payload())
	p := DNS(udp.Payload())
	if p.IsValid() != nil {
		t.Fatal("invalid dns packet")
	}

	entry, err := p.decode()
	if err != nil {
		t.Fatal("cannot decode", err)
	}
	r, ok := entry.IP4Records[netaddr.IPv4(35, 244, 67, 249)]
	if len(entry.IP4Records) != 1 || !ok || r.Name != "td-balancer-ause1-67-249.wixdns.net" {
		t.Fatalf("invalid packet %+v ", r)
	}
	r2, ok2 := entry.CNameRecords["www245.wixdns.net"]
	if len(entry.CNameRecords) != 4 || !ok2 {
		t.Fatalf("invalid cname packet %+v ", r2)
	}
}

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
	0x45, 0x00, 0x00, 0x7e, 0x00, 0x00, 0x40, 0x00, 0x3f, 0x11, 0xb8, 0x9c, 0xc0, 0xa8, 0x01, 0x01, // E..~..@.?.......
	0xc0, 0xa8, 0x00, 0x81, 0x00, 0x35, 0x81, 0xb1, 0x00, 0x6a, 0x07, 0x8d, 0xc4, 0x09, 0x81, 0x80, // .....5...j......
	0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x03, 0x32, 0x30, 0x33, 0x02, 0x36, 0x37, 0x03, // .........203.67.
	0x32, 0x35, 0x33, 0x02, 0x31, 0x37, 0x07, 0x69, 0x6e, 0x2d, 0x61, 0x64, 0x64, 0x72, 0x04, 0x61, // 253.17.in-addr.a
	0x72, 0x70, 0x61, 0x00, 0x00, 0x0c, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, // rpa.............
	0x38, 0x40, 0x00, 0x1f, 0x11, 0x61, 0x75, 0x73, 0x79, 0x64, 0x32, 0x2d, 0x76, 0x69, 0x70, 0x2d, // 8@...ausyd2-vip-
	0x62, 0x78, 0x2d, 0x30, 0x30, 0x33, 0x07, 0x61, 0x61, 0x70, 0x6c, 0x69, 0x6d, 0x67, 0x03, 0x63, // bx-003.aaplimg.c
	0x6f, 0x6d, 0x00, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // om...)........
}

func TestDNS_DecodePTR(t *testing.T) {

	ip := packet.IP4(wwwPTRResponse)
	udp := packet.UDP(ip.Payload())
	p := DNS(udp.Payload())
	if p.IsValid() != nil {
		t.Fatal("invalid dns packet")
	}

	entry, err := p.decode()
	if err != nil {
		t.Fatal("cannot decode", err)
	}
	r, ok := entry.PTRRecords["ausyd2-vip-bx-003.aaplimg.com"]
	if len(entry.PTRRecords) != 1 || !ok || r.IP != netaddr.IPv4(17, 253, 67, 203) {
		t.Fatalf("invalid dns rr %+v ", r)
	}
}

func TestDNS_ProcessDNS(t *testing.T) {
	session := testSession()
	dnsHandler, _ := New(session)
	Debug = true

	for _, v := range [][]byte{wwwYouTubeComResponse, wwwFacebookComAnswer, wwwBlockthekidsComResponse, wwwFacebookComAnswer} {
		ip := packet.IP4(v)
		udp := packet.UDP(ip.Payload())

		r, err := dnsHandler.ProcessDNS(nil, nil, udp.Payload())
		if err != nil {
			t.Fatalf("invalid process packet bltk %+v %s", r, err)
		}
	}
	if n := len(dnsHandler.DNSTable); n != 3 {
		t.Fatalf("invalid dns table len=%v want=3 ", n)
	}
	fmt.Printf("table %+v", dnsHandler.DNSTable)

}

func TestDNS_reverseDNS(t *testing.T) {
	session := testSession()
	dnsHandler, _ := New(session)
	Debug = true

	if err := ReverseDNS(netaddr.IPv4(172, 217, 167, 118)); err != nil {
		t.Fatal(err)
	}
	// =13.76.219.18
	if found := dnsHandler.DNSExist(netaddr.IPv4(13, 76, 219, 18)); found {
		t.Fatal("invalid entry")
	}

	dnsHandler.DNSLookupPTR(netaddr.IPv4(13, 76, 219, 18))

	if found := dnsHandler.DNSExist(netaddr.IPv4(13, 76, 219, 18)); !found {
		dnsHandler.PrintDNSTable()
		t.Fatal("invalid entry")
	}

	dnsHandler.DNSLookupPTR(netaddr.IPv4(13, 76, 219, 18))

	entry, found := dnsHandler.DNSTable["ptrentryname"]
	if !found || len(entry.IP4Records) != 1 {
		dnsHandler.PrintDNSTable()
		t.Fatal("invalid entry")
	}

}

// Benchmark_DNSConcurrentAccess test concurrent access performance
// Benchmark_DNSConcurrentAccess-8   	  114400	     10260 ns/op	    6267 B/op	      52 allocs/op
func Benchmark_DNSConcurrentAccess(b *testing.B) {
	session := testSession()
	dnsHandler, _ := New(session)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			for _, v := range [][]byte{wwwYouTubeComResponse, wwwFacebookComAnswer, wwwBlockthekidsComResponse, wwwFacebookComAnswer, wwwPTRResponse} {
				ip := packet.IP4(v)
				udp := packet.UDP(ip.Payload())

				r, err := dnsHandler.ProcessDNS(nil, nil, udp.Payload())
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
			e = dnsHandler.DNSFind("facebook.com")
			if e.Name != "facebook.com" {
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
