package icmp_spoofer

import (
	"testing"
	"time"

	"github.com/irai/packet"
)

func TestHandler_StartHunt(t *testing.T) {
	tc := setupTestHandler()
	defer tc.Close()

	h, _ := New6(tc.session)
	h.Router = &Router{Addr: routerLLAAddr}

	addr1 := packet.Addr{MAC: mac1, IP: ip1}
	h.StartHunt(addr1)

	addr2 := packet.Addr{MAC: mac2, IP: ip2}
	h.StartHunt(addr2)

	time.Sleep(time.Millisecond * 4)

	// invalid mac
	addr3 := packet.Addr{MAC: mac3, IP: ip3}
	h.StopHunt(addr3)

	h.StopHunt(addr1)
	h.StopHunt(addr2)

	// Lock and unlock to ensure no deadlock in test
	h.Mutex.Lock()
	if h.huntList.Len() != 0 {
		t.Errorf("error invalid huntlist len=%d want=0", h.huntList.Len())
	}
	h.Mutex.Unlock()
}

func TestHandler_ManyStartHunt(t *testing.T) {
	tc := setupTestHandler()
	defer tc.Close()

	h, _ := New6(tc.session)
	h.Router = &Router{Addr: routerLLAAddr}

	addr1 := packet.Addr{MAC: mac1, IP: ip6LLA1}
	h.StartHunt(addr1)

	addr2 := packet.Addr{MAC: mac1, IP: ip6LLA2}
	h.StartHunt(addr2)

	addr3 := packet.Addr{MAC: mac1, IP: ip6LLA3}
	h.StartHunt(addr3)

	h.Mutex.Lock()
	if h.huntList.Len() != 1 {
		t.Fatal("invalid number of ip in capture ", h.huntList.Len())
	}
	h.Mutex.Unlock()

	lla := packet.Addr{MAC: mac1, IP: ip6LLA1}
	h.StartHunt(lla)

	time.Sleep(time.Millisecond * 4)

	// Stop
	// Lock and unlock to ensure no deadlock in test
	h.StopHunt(addr3)
	h.Mutex.Lock()
	if h.huntList.Len() != 0 {
		t.Fatal("invalid number of ip in capture ", h.huntList.Len())
	}
	h.Mutex.Unlock()

	h.StopHunt(addr1)
	h.Mutex.Lock()
	if h.huntList.Len() != 0 {
		t.Fatal("invalid number of ip in capture ", h.huntList.Len())
	}
	h.Mutex.Unlock()

	h.StopHunt(lla)
	h.Mutex.Lock()
	if h.huntList.Len() != 0 {
		t.Fatal("invalid number of ip in capture ", h.huntList.Len())
	}
	h.Mutex.Unlock()

}
