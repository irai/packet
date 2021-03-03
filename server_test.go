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
		{name: "invalid", wantLen: 1, ether: ether},
	}
	Debug = true

	ctx, cancel := context.WithCancel(context.Background())

	inConn, outConn := TestNewBufferedConn()
	go TestReadAndDiscardLoop(ctx, outConn) // MUST read the out conn to avoid blocking the sender
	config := Config{Conn: inConn}
	h, err := config.New("eth0")
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
			if h.LANHosts.Len() != tt.wantLen {
				t.Errorf("%s: invalid LANHost table length want=%d got=%d", tt.name, tt.wantLen, h.LANHosts.Len())

			}
		})
	}
	cancel()
}
