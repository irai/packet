package dhcp4

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/irai/packet"
)

func TestAttach(t *testing.T) {
	tc := setupTestHandler()

	if err := tc.h.Close(); err != nil {
		panic(err)
	}

	tc2 := setupTestHandler()
	if err := tc2.h.Close(); err != nil {
		panic(err)
	}
	tc.Close()
}

func mustHex(b []byte) []byte {
	b = bytes.ReplaceAll(b, []byte{' '}, nil)
	n, err := hex.Decode(b, b)
	if err != nil {
		panic(err)
	}
	return b[:n]
}

/* sudo tcpdump -en -v -XX -t port 67 or port 68
84:11:9e:03:89:c0 > ff:ff:ff:ff:ff:ff, ethertype IPv4 (0x0800), length 357: (tos 0x0, ttl 64, id 42239, offset 0, flags [none], proto UDP (17), length 343)
    0.0.0.0.68 > 255.255.255.255.67: BOOTP/DHCP, Request from 84:11:9e:03:89:c0, length 315, xid 0x4eb132d6, secs 1, Flags [none]
	  Client-Ethernet-Address 84:11:9e:03:89:c0
	  Vendor-rfc1048 Extensions
	    Magic Cookie 0x63825363
	    DHCP-Message Option 53, length 1: Request
	    Client-ID Option 61, length 7: ether 84:11:9e:03:89:c0
	    Requested-IP Option 50, length 4: 192.168.0.134
	    MSZ Option 57, length 2: 1500
	    Vendor-Class Option 60, length 12: "dhcpcd-5.5.6"
	    Hostname Option 12, length 24: "android-d8ea006c9d2690b9"
	    Parameter-Request Option 55, length 10:
	      Subnet-Mask, Static-Route, Default-Gateway, Domain-Name-Server
	      Domain-Name, MTU, BR, Lease-Time
	      RN, RB
*/
var android_req1 = []byte(
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

/**
84:11:9e:03:89:c0 > ff:ff:ff:ff:ff:ff, ethertype IPv4 (0x0800), length 357: (tos 0x0, ttl 64, id 46952, offset 0, flags [none], proto UDP (17), length 343)
0.0.0.0.68 > 255.255.255.255.67: BOOTP/DHCP, Request from 84:11:9e:03:89:c0, length 315, xid 0x40d78b0, Flags [none]
	Client-Ethernet-Address 84:11:9e:03:89:c0
	Vendor-rfc1048 Extensions
	Magic Cookie 0x63825363
	DHCP-Message Option 53, length 1: Request
	Client-ID Option 61, length 7: ether 84:11:9e:03:89:c0
	Requested-IP Option 50, length 4: 192.168.0.134
	MSZ Option 57, length 2: 1500
	Vendor-Class Option 60, length 12: "dhcpcd-5.5.6"
	Hostname Option 12, length 24: "android-d8ea006c9d2690b9"
	Parameter-Request Option 55, length 10:
		Subnet-Mask, Static-Route, Default-Gateway, Domain-Name-Server
		Domain-Name, MTU, BR, Lease-Time
		RN, RB
*/
var android_req2 = []byte(
	`ffff ffff ffff 8411 9e03 89c0 0800 4500` + //  ..............E.
		`0157 b768 0000 4011 c22e 0000 0000 ffff` + //  .W.h..@.........
		`ffff 0044 0043 0143 8bdc 0101 0600 040d` + //  ...D.C.C........
		`78b0 0000 0000 0000 0000 0000 0000 0000` + //  x...............
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

/**
		84:11:9e:03:89:c0 > ff:ff:ff:ff:ff:ff, ethertype IPv4 (0x0800), length 351: (tos 0x0, ttl 64, id 15125, offset 0, flags [none], proto UDP (17), length 337)
    0.0.0.0.68 > 255.255.255.255.67: BOOTP/DHCP, Request from 84:11:9e:03:89:c0, length 309, xid 0xfc07f1a1, Flags [none]
	  Client-Ethernet-Address 84:11:9e:03:89:c0
	  Vendor-rfc1048 Extensions
	    Magic Cookie 0x63825363
	    DHCP-Message Option 53, length 1: Discover
	    Client-ID Option 61, length 7: ether 84:11:9e:03:89:c0
	    MSZ Option 57, length 2: 1500
	    Vendor-Class Option 60, length 12: "dhcpcd-5.5.6"
	    Hostname Option 12, length 24: "android-d8ea006c9d2690b9"
	    Parameter-Request Option 55, length 10:
	      Subnet-Mask, Static-Route, Default-Gateway, Domain-Name-Server
	      Domain-Name, MTU, BR, Lease-Time
	      RN, RB
*/
var android_discover = []byte(`ffff ffff ffff 8411 9e03 89c0 0800 4500` + //  ..............E.
	`0151 3b15 0000 4011 3e88 0000 0000 ffff` + //  .Q;...@.>.......
	`ffff 0044 0043 013d 102f 0101 0600 fc07` + //  ...D.C.=./......
	`f1a1 0000 0000 0000 0000 0000 0000 0000` + //  ................
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
	`0000 0000 0000 6382 5363 3501 013d 0701` + //  ......c.Sc5..=..
	`8411 9e03 89c0 3902 05dc 3c0c 6468 6370` + //  ......9...<.dhcp
	`6364 2d35 2e35 2e36 0c18 616e 6472 6f69` + //  cd-5.5.6..androi
	`642d 6438 6561 3030 3663 3964 3236 3930` + //  d-d8ea006c9d2690
	`6239 370a 0121 0306 0f1a 1c33 3a3b ff`) //  b97..!.....3:;.

/**
	84:11:9e:03:89:c0 > ff:ff:ff:ff:ff:ff, ethertype IPv4 (0x0800), length 363: (tos 0x0, ttl 64, id 51592, offset 0, flags [none], proto UDP (17), length 349)
    0.0.0.0.68 > 255.255.255.255.67: BOOTP/DHCP, Request from 84:11:9e:03:89:c0, length 321, xid 0xfc07f1a1, Flags [none]
	  Client-Ethernet-Address 84:11:9e:03:89:c0
	  Vendor-rfc1048 Extensions
	    Magic Cookie 0x63825363
	    DHCP-Message Option 53, length 1: Request
	    Client-ID Option 61, length 7: ether 84:11:9e:03:89:c0
	    Requested-IP Option 50, length 4: 192.168.0.131
	    Server-ID Option 54, length 4: 192.168.0.129
	    MSZ Option 57, length 2: 1500
	    Vendor-Class Option 60, length 12: "dhcpcd-5.5.6"
	    Hostname Option 12, length 24: "android-d8ea006c9d2690b9"
	    Parameter-Request Option 55, length 10:
	      Subnet-Mask, Static-Route, Default-Gateway, Domain-Name-Server
	      Domain-Name, MTU, BR, Lease-Time
	      RN, RB
*/
var android_req3 = []byte(`ffff ffff ffff 8411 9e03 89c0 0800 4500` + //  ..............E.
	`015d c988 0000 4011 b008 0000 0000 ffff` + //  .]....@.........
	`ffff 0044 0043 0149 23b9 0101 0600 fc07` + //  ...D.C.I#.......
	`f1a1 0000 0000 0000 0000 0000 0000 0000` + //  ................
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
	`8411 9e03 89c0 3204 c0a8 0083 3604 c0a8` + //  ......2.....6...
	`0081 3902 05dc 3c0c 6468 6370 6364 2d35` + //  ..9...<.dhcpcd-5
	`2e35 2e36 0c18 616e 6472 6f69 642d 6438` + //  .5.6..android-d8
	`6561 3030 3663 3964 3236 3930 6239 370a` + //  ea006c9d2690b97.
	`0121 0306 0f1a 1c33 3a3b ff`) //  .!.....3:;.

func TestHandler_handleRequest(t *testing.T) {
	tests := []struct {
		name          string
		p             []byte
		updateReqIP   bool // indicate if we want to update the offer
		dhcp          DHCP4
		wantErr       bool
		wantReplyType MessageType
	}{
		{name: "req1", wantErr: false, wantReplyType: NAK, p: android_req1},
		{name: "req2", wantErr: false, wantReplyType: NAK, p: android_req1},
		{name: "req3", wantErr: false, wantReplyType: NAK, p: android_req1},
		{name: "req4", wantErr: false, wantReplyType: NAK, p: android_req2},
		{name: "discover", wantErr: false, wantReplyType: Offer, p: android_discover},
		{name: "req5", wantErr: false, wantReplyType: ACK, updateReqIP: true, p: android_req3},
	}

	Debug = false
	os.Remove(testDHCPFilename)
	tc := setupTestHandler()
	defer tc.Close()

	var offerXID []byte
	var offerIP netip.Addr
	buffer := make([]byte, 1500)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := copy(buffer, mustHex(tt.p)) // make sure the buffer is large enough for an ethernet paccket
			ether := packet.Ether(buffer[:n])
			// ip := packet.IP4(ether.Payload())
			// udp := packet.UDP(ip.Payload())
			frame, err := tc.session.Parse(ether)
			if err != nil {
				panic(err)
			}
			dhcp := DHCP4(frame.Payload())
			if err := dhcp.IsValid(); err != nil {
				t.Fatalf("%s: Handler.handleRequest() unexpected error %s", tt.name, err)
			}

			// update request to offer IP if desired
			if options := dhcp.ParseOptions(); tt.updateReqIP && bytes.Equal(dhcp.XId(), offerXID) && offerIP.Is4() {
				fmt.Println("dhcp4 test updating IP", offerIP, offerXID, dhcp.ParseOptions())
				options[OptionRequestedIPAddress] = offerIP.AsSlice()
				n := dhcp.appendOptions(options, options[OptionParameterRequestList])
				dhcp = dhcp[:240+n]
				if err := dhcp.IsValid(); err != nil {
					t.Fatalf("%s: Handler.handleRequest() unexpected error %s", tt.name, err)
				}
				fmt.Println("dhcp4 request updating IP", dhcp, dhcp.ParseOptions())
			}

			err = tc.h.ProcessPacket(frame)
			if (err != nil) != tt.wantErr {
				t.Fatalf("%s: Handler.handleRequest() unexpected error %s", tt.name, err)
			}
			select {
			case msg := <-tc.notifyReply:
				frame, err = tc.session.Parse(msg)
				if err != nil {
					panic(err)
				}
				// dhcp := DHCP4(packet.UDP(packet.IP4(packet.Ether(msg).Payload()).Payload()).Payload())
				dhcp := DHCP4(frame.Payload())
				options := dhcp.ParseOptions()
				tmp, ok := options[OptionDHCPMessageType]
				if !ok || len(tmp) != 1 {
					t.Fatalf("%s: Handler.handleRequest() invalid message type got=%v, want=%v", tt.name, tmp, tt.wantReplyType)
				}
				mt := MessageType(tmp[0])
				if mt != tt.wantReplyType {
					t.Fatalf("%s: Handler.handleRequest() invalid message type got=%v, want=%v", tt.name, mt, tt.wantReplyType)
					return
				}
				if mt == Offer {
					offerXID = packet.CopyBytes(dhcp.XId())
					offerIP = dhcp.YIAddr()
				}
			case <-time.After(time.Millisecond * 10):
				t.Fatal("failed to receive reply")
			}
		})
	}
}
