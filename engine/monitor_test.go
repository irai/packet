package engine

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"testing"
	"time"

	"github.com/irai/packet"
)

func TestHandler_threeMinuteChecker(t *testing.T) {
	packet.Debug = true
	nicInfo := packet.NICInfo{
		HostMAC:     hostMAC,
		HostIP4:     net.IPNet{IP: hostIP4, Mask: net.IPv4Mask(255, 255, 255, 0)},
		RouterIP4:   net.IPNet{IP: routerIP4, Mask: net.IPv4Mask(255, 255, 255, 0)},
		RouterMAC:   routerMAC,
		RouterAddr4: packet.Addr{MAC: routerMAC, IP: routerIP4},
		HomeLAN4:    homeLAN,
	}
	inConn, _ := packet.TestNewBufferedConn()
	engine, err := Config{Conn: inConn, NICInfo: &nicInfo}.NewEngine("eth0")
	if err != nil {
		t.Fatal("engine did not stop as expected", err)
	}

	go func() {
		if err := engine.ListenAndServe(context.TODO()); err != nil {
			t.Error("engine did not stop as expected", err)
			return
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c)

	time.Sleep(time.Millisecond * 5)
	ipHeartBeat = 0
	engine.threeMinuteChecker(time.Now())

	select {
	case <-time.After(time.Millisecond * 5):
		t.Error("engine did not stop as expected")
	case <-c:
		fmt.Printf("got signal")
	}
}
