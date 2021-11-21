package packet

import (
	"testing"
	"time"
)

func TestSession_SetOnline(t *testing.T) {
	session := setupTestHandler()
	// first host
	host1, _ := session.findOrCreateHost(Addr{MAC: mac1, IP: ip1})
	session.SetOnline(host1)

	// second host
	host2, _ := session.findOrCreateHost(Addr{MAC: mac1, IP: ip2})
	session.SetOnline(host2)

	// must get have 3 notifications - online, offline, online
	for i := 0; i < 3; i++ {
		select {
		case <-session.C:
		case <-time.After(time.Second):
			t.Fatal("did not receive notification number", i)
		}
	}
}
