package packet

import (
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/irai/packet/fastlog"
	"golang.org/x/net/ipv6"
	"inet.af/netaddr"
)

func Test_IP6Lib(t *testing.T) {
	// simple sanity test
	_, err := netaddr.ParseIP("2001:4479:1d01:2401::")
	if err != nil {
		t.Error("invalid IP ", err)
	}
}

func TestICMP4Redirect_IsValid(t *testing.T) {
	tests := []struct {
		name    string
		p       []byte
		wantErr bool
	}{
		/**
		TODO: capture ICMP4 redirect test frames. these are wrong
		{name: "redirect", wantErr: false, p: []byte{0x74, 0x79, 0x70, 0x65, 0x3d, 0x39, 0x20, 0x63, 0x6f, 0x64, 0x65, 0x3d, 0x30, 0x20, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x4c, 0x65, 0x6e, 0x3d, 0x31, 0x38, 0x2c, 0x20, 0x64, 0x61, 0x74, 0x61, 0x3d, 0x30, 0x78, 0x63, 0x30, 0x20, 0x61, 0x38, 0x20, 0x30, 0x30, 0x20, 0x30, 0x31, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30}},
		{name: "redirect", wantErr: false, p: []byte{0x74, 0x79, 0x70, 0x65, 0x3d, 0x39, 0x20, 0x63, 0x6f, 0x64, 0x65, 0x3d, 0x30, 0x20, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x4c, 0x65, 0x6e, 0x3d, 0x31, 0x38, 0x2c, 0x20, 0x64, 0x61, 0x74, 0x61, 0x3d, 0x30, 0x78, 0x63, 0x30, 0x20, 0x61, 0x38, 0x20, 0x30, 0x30, 0x20, 0x30, 0x31, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30}},
		{name: "redirect", wantErr: false, p: []byte{0x74, 0x79, 0x70, 0x65, 0x3d, 0x39, 0x20, 0x63, 0x6f, 0x64, 0x65, 0x3d, 0x30, 0x20, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x4c, 0x65, 0x6e, 0x3d, 0x31, 0x38, 0x2c, 0x20, 0x64, 0x61, 0x74, 0x61, 0x3d, 0x30, 0x78, 0x32, 0x38, 0x20, 0x30, 0x34, 0x20, 0x30, 0x31, 0x20, 0x34, 0x64, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30}},
		{name: "redirect", wantErr: false, p: []byte{0x74, 0x79, 0x70, 0x65, 0x3d, 0x39, 0x20, 0x63, 0x6f, 0x64, 0x65, 0x3d, 0x30, 0x20, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x4c, 0x65, 0x6e, 0x3d, 0x31, 0x38, 0x2c, 0x20, 0x64, 0x61, 0x74, 0x61, 0x3d, 0x30, 0x78, 0x32, 0x38, 0x20, 0x30, 0x34, 0x20, 0x30, 0x31, 0x20, 0x34, 0x64, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30, 0x20, 0x30, 0x30}},
		**/
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ether := Ether(tt.p)
			fmt.Println("test icmp redirect", ether)
			ip := IP4(ether.Payload())
			fmt.Println("test icmp redirect", ip)
			p := ICMP4Redirect(ip.Payload())
			if err := p.IsValid(); (err != nil) != tt.wantErr {
				t.Errorf("ICMP4Redirect.IsValid() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			fmt.Println("test icmp redirect", p)
		})
	}
}

/* sudo tcpdump -en -v -XX -t port 67 or port 68
48:86:e8:28:54:30 > 33:33:ff:42:29:a9, ethertype IPv6 (0x86dd), length 86: (hlim 255, next-header ICMPv6 (58) payload length: 32)
fe80::c471:bcf1:a434:cffc > ff02::1:ff42:29a9: [icmp6 sum ok] ICMP6, neighbor solicitation, length 32, who has fe80::36e8:94ff:fe42:29a9
          source link-address option (1), length 8 (1): 48:86:e8:28:54:30
*/
var icmp6_ns_req = []byte(
	`3333 ff42 29a9 4886 e828 5430 86dd 6000` + //  33.B).H..(T0..`.
		`0000 0020 3aff fe80 0000 0000 0000 c471` + //  ....:..........q
		`bcf1 a434 cffc ff02 0000 0000 0000 0000` + //  ...4............
		`0001 ff42 29a9 8700 e469 0000 0000 fe80` + //  ...B)....i......
		`0000 0000 0000 36e8 94ff fe42 29a9 0101` + //  ......6....B)...
		`4886 e828 5430                         `) //  H..(T0

/*
34:e8:94:42:29:a9 > 33:33:00:00:00:01, ethertype IPv6 (0x86dd), length 142: (hlim 255, next-header ICMPv6 (58) payload length: 88)
fe80::36e8:94ff:fe42:29a9 > ff02::1: [icmp6 sum ok] ICMP6, router advertisement, length 88
        hop limit 64, Flags [other stateful], pref high, router lifetime 30s, reachable time 0ms, retrans timer 0ms
          prefix info option (3), length 32 (4): 2001:4479:1d00:7002::/64, Flags [onlink, auto], valid time 300s, pref. time 120s
          rdnss option (25), length 24 (3):  lifetime 10s, addr: fe80::36e8:94ff:fe42:29a9
          mtu option (5), length 8 (1):  1500
          source link-address option (1), length 8 (1): 34:e8:94:42:29:a9
*/
var icmp6_ra_req = []byte(
	`3333 0000 0001 34e8 9442 29a9 86dd 6000` + //  33....4..B)...`.
		`0000 0058 3aff fe80 0000 0000 0000 36e8` + //  ...X:.........6.
		`94ff fe42 29a9 ff02 0000 0000 0000 0000` + //  ...B)...........
		`0000 0000 0001 8600 86b4 4048 001e 0000` + //  ..........@H....
		`0000 0000 0000 0304 40c0 0000 012c 0000` + //  ........@....,..
		`0078 0000 0000 2001 4479 1d00 7002 0000` + //  .x......Dy..p...
		`0000 0000 0000 1903 8000 0000 000a fe80` + //  ................
		`0000 0000 0000 36e8 94ff fe42 29a9 0501` + //  ......6....B)...
		`0000 0000 05dc 0101 34e8 9442 29a9     `) //  ........4..B).

func Test_icmp6(t *testing.T) {
	tests := []struct {
		name    string
		p       []byte
		wantErr bool
	}{
		{name: "ns", wantErr: false, p: icmp6_ns_req},
		{name: "ra", wantErr: false, p: icmp6_ra_req},
	}

	// Logger.SetLevel(fastlog.LevelDebug)
	session, _ := testSession()

	buffer := make([]byte, 1500)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := copy(buffer, mustHex(tt.p))
			frame, err := session.Parse(buffer[:n])

			if (err != nil) != tt.wantErr {
				t.Errorf("%s: unexpected error = %v, wantErr %v", tt.name, err, tt.wantErr)
				return
			}

			if frame.PayloadID != PayloadICMP6 {
				t.Errorf("%s: invalid payloadID = %v", tt.name, frame.PayloadID)
				return
			}

			icmp6Frame := ICMP(frame.Payload())
			if icmp6Frame.IsValid() != nil {
				t.Errorf("%s: unexpected icmp error = %v ", tt.name, err)
				return
			}

			switch ipv6.ICMPType(icmp6Frame.Type()) {
			case ipv6.ICMPTypeNeighborAdvertisement: // 0x88
				frame := ICMP6NeighborAdvertisement(icmp6Frame)
				if err := frame.IsValid(); err != nil {
					t.Errorf("icmp6 : invalid NA msg: %v", err)
					return
				}
			case ipv6.ICMPTypeNeighborSolicitation: // 0x87
				frame := ICMP6NeighborSolicitation(icmp6Frame)
				if err := frame.IsValid(); err != nil {
					t.Errorf("icmp6 : invalid NS msg: %v", err)
					return
				}
			case ipv6.ICMPTypeRouterAdvertisement: // 0x86
				frame := ICMP6RouterAdvertisement(icmp6Frame)
				if err := frame.IsValid(); err != nil {
					t.Errorf("icmp6 : invalid RA msg: %v", err)
					return
				}
			case ipv6.ICMPTypeRouterSolicitation:
				frame := ICMP6RouterSolicitation(icmp6Frame)
				if err := frame.IsValid(); err != nil {
					t.Errorf("icmp6 : invalid RS msg: %v", err)
					return
				}
			case ipv6.ICMPTypeEchoReply: // 0x81
				echo := ICMPEcho(icmp6Frame)
				if err := echo.IsValid(); err != nil {
					t.Errorf("icmp6 : invalid echo msg: %v", err)
					return
				}
			case ipv6.ICMPTypeEchoRequest: // 0x80
				echo := ICMPEcho(icmp6Frame)
				if err := echo.IsValid(); err != nil {
					t.Errorf("icmp6 : invalid echo msg: %v", err)
					return
				}

			case ipv6.ICMPTypeMulticastListenerReport:
				// TODO: implement

			case ipv6.ICMPTypeVersion2MulticastListenerReport:
				// TODO: implement

			case ipv6.ICMPTypeMulticastListenerQuery:
				// TODO: implement

			case ipv6.ICMPTypeRedirect:
				redirect := ICMP6Redirect(icmp6Frame)
				if err := redirect.IsValid(); err != nil {
					t.Errorf("icmp6 : invalid redirect msg: %v", err)
					return
				}

			case ipv6.ICMPTypeDestinationUnreachable:
				// TODO: implement
			}
		})
	}
}

func Benchmark_Ping256(b *testing.B) {
	session, _ := testSession()
	defer session.Close()
	for i := 0; i < b.N; i++ {
		ping256(session)
	}
}

func ping256(s *Session) {
	channel := make(chan net.IP, 20)
	srcIP := hostIP4
	for i := 1; i < 255; i++ {
		ip := CopyIP(srcIP).To4() // new buffer, we are sending this in the channel
		ip[3] = uint8(i)
		go func(ip net.IP) {
			if s.Ping6(hostAddr, Addr{IP: ip}, time.Second*2) != nil {
				channel <- net.IPv4zero
				return
			}
			channel <- ip
		}(ip)
		time.Sleep(time.Millisecond * 5)
	}
	for i := 1; i < 255; i++ {
		ip := <-channel
		if !ip.Equal(net.IPv4zero) {
			fmt.Printf("Found client ip=%s", ip)
		}
	}
}

func TestSession_Ping(t *testing.T) {
	session, client := testSession()
	defer session.Close()

	Logger.SetLevel(fastlog.LevelDebug)

	addr := Addr{MAC: mac1, IP: ip1}
	go func() {
		buf := make([]byte, EthMaxSize)
		n, _, err := client.ReadFrom(buf)
		if err != nil {
			return
		}
		ether := Ether(buf[:n])
		ip4 := IP4(ether.Payload())
		echo := ICMPEcho(ip4.Payload())
		if err := echo.IsValid(); err != nil {
			panic(err)
		}
		out := make([]byte, EthMaxSize)
		ether = EncodeEther(out, syscall.ETH_P_IP, addr.MAC, session.NICInfo.HostAddr4.MAC)
		ip4 = EncodeIP4(ether.Payload(), 64, addr.IP, session.NICInfo.HostAddr4.IP)
		e := EncodeICMPEcho(ip4.Payload(), ICMP4TypeEchoReply, echo.Code(), echo.EchoID(), echo.EchoSeq(), echo.EchoData())
		ip4 = ip4.SetPayload(e, syscall.IPPROTO_ICMP)
		ether, _ = ether.SetPayload(ip4)
		session.Parse(ether)
	}()

	if err := session.Ping(addr, time.Millisecond*100); err != nil {
		t.Errorf("Session.Ping() error = %v", err)
	}

	if err := session.Ping(addr, time.Millisecond*100); err != ErrTimeout {
		t.Errorf("Session.Ping() error = %v", err)
	}
}
