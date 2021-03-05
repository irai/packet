// +build !arp

package dhcp4

import (
	"os"
	"testing"

	log "github.com/sirupsen/logrus"
)

func Test_DHCP_SaveAndLoad(t *testing.T) {

	os.Remove(testDHCPFilename)

	tc := setupTestHandler()
	defer tc.Close()
	var err error

	entry := tc.h.net1.newLease(StateDiscovery, mac0, mac0, nil, nil)
	entry.State = StateAllocated

	entry = tc.h.net1.newLease(StateDiscovery, mac0, mac0, nil, nil)
	entry.State = StateAllocated
	savedIP := entry.IP

	// Discovery will be discarded on load
	entry = tc.h.net2.newLease(StateDiscovery, mac0, mac0, nil, nil)
	entry.State = StateDiscovery

	entry = tc.h.net2.newLease(StateDiscovery, mac0, mac0, nil, nil)
	entry.State = StateAllocated

	entry = tc.h.net2.newLease(StateDiscovery, mac0, mac0, nil, nil)
	entry.State = StateAllocated

	entry = tc.h.net2.newLease(StateDiscovery, mac0, mac0, nil, nil)
	entry.State = StateAllocated

	err = tc.h.saveConfig(testDHCPFilename)
	if err != nil {
		log.Fatal("cannot save", err)
	}

	// Reloading will remove discovery state
	tc2 := setupTestHandler()

	entry = tc2.h.net1.findIP(savedIP)
	count1, _ := tc2.h.net1.countLeases()
	count2, _ := tc2.h.net2.countLeases()
	if entry == nil || count1 != 2 || count2 != 3 {
		tc2.h.net1.printSubnet()
		tc2.h.net2.printSubnet()
		log.Fatal("invalid load ", count1, count2)
	}
}

func Test_DHCP_Config(t *testing.T) {

	os.Remove(testDHCPFilename)
	tc := setupTestHandler()
	defer tc.Close()
	var err error

	/**
	h, err := New(nets[0].home, nets[0].netfilter, testDHCPFilename)
	if err != nil {
		t.Fatal("cannot create handler ", err)
	}
	**/

	entry := tc.h.net1.newLease(StateDiscovery, mac0, mac0, nil, nil)
	entry.State = StateAllocated
	entry = tc.h.net1.newLease(StateDiscovery, mac0, mac0, nil, nil)
	entry.State = StateAllocated
	savedIP := entry.IP

	// createHandler an invalid config
	entry = tc.h.net2.newLease(StateDiscovery, mac0, mac0, nil, nil)
	entry.State = StateAllocated
	entry = tc.h.net2.newLease(StateDiscovery, mac0, mac0, nil, nil)
	entry.State = StateAllocated

	err = tc.h.saveConfig(testDHCPFilename)
	if err != nil {
		log.Fatal("cannot save", err)
	}

	// Reloading should fix the invalid config
	tc.h.Detach()
	tc = setupTestHandler()
	// tc.h, err = Attach(tc.packet, nets[0].home, nets[0].netfilter, testDHCPFilename)
	if err != nil {
		log.Fatal("cannot reload", err)
	}

	entry = tc.h.net1.findIP(savedIP)
	if entry == nil {
		tc.h.net1.printSubnet()
		log.Fatal("invalid nil entry ", entry)
	}

}
