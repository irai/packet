package packet

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"testing"
	"time"
)

func TestSession_SetOnline(t *testing.T) {
	session := setupTestHandler()
	// first host
	host1, _ := session.findOrCreateHostWithLock(Addr{MAC: mac1, IP: ip1})
	session.SetOnline(Frame{Host: host1})

	// second host
	host2, _ := session.findOrCreateHostWithLock(Addr{MAC: mac1, IP: ip2})
	session.SetOnline(Frame{Host: host2})

	// must get have 3 notifications - online, offline, online
	for i := 0; i < 3; i++ {
		select {
		case <-session.C:
		case <-time.After(time.Second):
			t.Fatal("did not receive notification number", i)
		}
	}
}

func TestHandler_SignalNICStopped(t *testing.T) {
	Debug = true
	nicInfo := NICInfo{
		HostMAC:     hostMAC,
		HostIP4:     net.IPNet{IP: hostIP4, Mask: net.IPv4Mask(255, 255, 255, 0)},
		RouterIP4:   net.IPNet{IP: routerIP4, Mask: net.IPv4Mask(255, 255, 255, 0)},
		RouterMAC:   routerMAC,
		RouterAddr4: Addr{MAC: routerMAC, IP: routerIP4},
		HomeLAN4:    homeLAN,
	}
	inConn, _ := TestNewBufferedConn()

	c := make(chan os.Signal, 1)
	signal.Notify(c)

	keep := monitorNICFrequency
	defer func() { monitorNICFrequency = keep }()
	monitorNICFrequency = time.Millisecond * 3

	session, err := Config{Conn: inConn, NICInfo: &nicInfo}.NewSession()
	if err != nil {
		t.Fatal("engine did not stop as expected", err)
	}

	select {
	case <-time.After(time.Millisecond * 5):
		t.Error("engine did not stop as expected")
		fmt.Println(session.NICInfo)
	case <-c:
		fmt.Printf("got signal")
		fmt.Println(session.NICInfo)
	}
}
