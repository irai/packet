package packet

import (
	"context"
	"syscall"
	"testing"
	"time"
)

func TestHandler_ListenAndServe(t *testing.T) {
	buf := make([]byte, EthMaxSize) // allocate in the stack
	mypayload := []byte{0xf, 0xb, 0xa}
	ether := EtherMarshalBinary(buf, syscall.ETH_P_IPV6, routerMAC, mac2)
	if !ether.IsValid() {
		panic("invalid ether")
	}
	ip6 := IP6MarshalBinary(ether.Payload(), 1, ip6LLAHost, ip6LLA2)
	ip6, _ = ip6.AppendPayload(mypayload, 25) // 25 as a test id
	ether, _ = ether.AppendPayload(ip6)
	tests := []struct {
		name    string
		ether   []byte
		wantLen int
	}{
		{name: "invalid", wantLen: 2, ether: ether},
	}
	Debug = true

	ctx, cancel := context.WithCancel(context.Background())

	inConn, outConn := TestNewBufferedConn()
	go TestReadAndDiscardLoop(ctx, outConn) // MUST read the out conn to avoid blocking the sender
	config := Config{Conn: inConn}
	h, err := config.NewEngine("eth0")
	if err != nil {
		panic(err)
	}
	defer h.Close()

	go func() {
		if err := h.ListenAndServe(ctx); err != nil {
			t.Errorf("ListenAndServe terminated with error:%s", err)
		}
	}()

	time.Sleep(time.Millisecond * 20)
	Debug = true
	DebugIP6 = true

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := outConn.WriteTo(tt.ether, nil); err != nil {
				t.Errorf("%s: Handler.ListenAndServe() writeTo error: %s", tt.name, err)
			}
			time.Sleep(time.Millisecond * 20)
			if len(h.LANHosts.Table) != tt.wantLen {
				t.Errorf("%s: invalid LANHost table length want=%d got=%d", tt.name, tt.wantLen, len(h.LANHosts.Table))

			}
		})
	}
	cancel()
}

/****
func TestHandler_OnlineOfflineState(t *testing.T) {
	options := []dhcp4.Option{}
	oDNS := dhcp4.Option{Code: dhcp4.OptionDomainNameServer, Value: []byte{}}

	// packet.DebugIP4 = true
	// Debug = true
	tc := setupTestHandler()
	defer tc.Close()

	tests := []struct {
		name          string
		packet        dhcp4.DHCP4
		wantResponse  bool
		tableLen      int
		responseCount int
		srcAddr       Addr
		dstAddr       Addr
	}{
		{name: "discover-mac1", wantResponse: true, responseCount: 1,
			packet: dhcp4.RequestPacket(dhcp4.Discover, mac1, ip1, []byte{0x01}, false, append(options, oDNS)), tableLen: 5,
			srcAddr: Addr{MAC: routerMAC, IP: routerIP4, Port: DHCP4ClientPort},
			dstAddr: Addr{MAC: mac1, IP: ip1, Port: DHCP4ServerPort}},
		{name: "request-mac1", wantResponse: true, responseCount: 1,
			packet: dhcp4.RequestPacket(dhcp4.Request, mac1, ip1, []byte{0x01}, false, append(options, oDNS)), tableLen: 5,
			srcAddr: Addr{MAC: routerMAC, IP: routerIP4, Port: DHCP4ClientPort},
			dstAddr: Addr{MAC: mac1, IP: ip1, Port: DHCP4ServerPort}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := sendPacket(tc.outConn, tt.srcAddr, tt.dstAddr, tt.packet); err != nil {
				t.Errorf("DHCPHandler.handleDiscover() error sending packet error=%s", err)
				return
			}
			time.Sleep(time.Millisecond * 10)

			if tt.responseCount != len(tc.responseTable) {
				t.Errorf("DHCPHandler.handleDiscover() invalid response count=%d want=%d", len(tc.responseTable), tt.responseCount)
			}
		})
	}
}
***/
