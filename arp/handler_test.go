package arp

import (
	"context"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"log"

	"github.com/irai/packet"
	"github.com/irai/packet/raw"
)

func newEtherPacket(hType uint16, srcMAC net.HardwareAddr, dstMAC net.HardwareAddr) raw.Ether {
	p, err := raw.EtherMarshalBinary(nil, hType, srcMAC, dstMAC)
	if err != nil {
		panic(err)
	}
	return p
}

func newPacket(op uint16, sMAC net.HardwareAddr, sIP net.IP, tMAC net.HardwareAddr, tIP net.IP) ARP {
	p, err := ARPMarshalBinary(nil, op, sMAC, sIP, tMAC, tIP)
	if err != nil {
		panic(err)
	}
	return p
}

type notificationCounter struct {
	onlineCounter  int
	offlineCounter int
}

func addNotification(ctx context.Context, h *Handler) *notificationCounter {
	channel := make(chan MACEntry, 10)
	n := &notificationCounter{}
	h.AddNotificationChannel(channel)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case entry := <-channel:
				if entry.Online {
					n.onlineCounter++
					// log.Print("got notification online", entry.String(), n.onlineCounter)
				} else {
					n.offlineCounter++
					// log.Print("got notification offline", entry.String(), n.offlineCounter)
				}
			}
		}
	}()

	return n
}

func testHandler(t *testing.T) (*Handler, net.PacketConn) {

	all, _ := net.Interfaces()

	config := Config{
		NIC:      all[0].Name,
		HostMAC:  hostMAC,
		HostIP:   hostIP,
		RouterIP: routerIP, HomeLAN: homeLAN,
		FullNetworkScanInterval: time.Second * 60,
		ProbeInterval:           time.Second * 1,
		OfflineDeadline:         time.Second * 2,
		PurgeDeadline:           time.Second * 4,
	}

	arpHandler, conn, _ := NewTestHandler(config, nil)

	return arpHandler, conn
}

func Test_ARPRequests(t *testing.T) {
	//Debug = true
	// log.SetLevel(log.DebugLevel)
	h, listener := testHandler(t)

	packet.Debug = true

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server, _ := packet.Config{Conn: listener}.New("")
	server.ARPHook("arp", h.ProcessPacket)
	go func() {
		if err := server.ListenAndServe(ctx); err != nil {
			panic(err)
		}
	}()

	var wg sync.WaitGroup
	go func() {
		wg.Add(1)
		h.ListenAndServe(ctx)
		wg.Done()
	}()

	tests := []struct {
		name    string
		ether   raw.Ether
		arp     ARP
		wantErr error
		wantLen int
		wantIPs int
	}{
		{name: "whois1",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac1, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac2, ip2, zeroMAC, ip3),
			wantErr: nil, wantLen: 1, wantIPs: 1},
		{name: "whois1-dup2",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac1, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac2, ip2, zeroMAC, ip3),
			wantErr: nil, wantLen: 1, wantIPs: 1},
		{name: "whois1-dup3",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac1, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac2, ip2, zeroMAC, ip3),
			wantErr: nil, wantLen: 1, wantIPs: 1},
		{name: "whois2",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac3, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac3, ip3, zeroMAC, routerIP),
			wantErr: nil, wantLen: 2, wantIPs: 1},
		{name: "announce-ip4",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac4, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac4, ip4, zeroMAC, ip4),
			wantErr: nil, wantLen: 3, wantIPs: 1},
		{name: "router",
			ether:   newEtherPacket(syscall.ETH_P_ARP, routerMAC, EthernetBroadcast),
			arp:     newPacket(OperationRequest, zeroMAC, routerIP, zeroMAC, ip3),
			wantErr: nil, wantLen: 3, wantIPs: 0},
		{name: "probe",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac2, net.IPv4zero.To4(), zeroMAC, ip4),
			wantErr: nil, wantLen: 3, wantIPs: 0},
		{name: "localink",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac2, localIP, zeroMAC, localIP2),
			wantErr: nil, wantLen: 3, wantIPs: 0},
		/***
		{name:"announceRouter", newPacket(OperationRequest, zeroMAC, routerIP, zeroMAC, routerIP), nil, 3, 0},
		{name:"announceHost", newPacket(OperationRequest, hostMAC, hostIP, zeroMAC, hostIP), nil, 3, 0},
		{name:"host", newPacket(OperationRequest, hostMAC, hostIP, zeroMAC, ip4), nil, 3, 0},
		{name:"announce5", newPacket(OperationRequest, mac5, ip5, zeroMAC, ip5), nil, 4, 1},
		{name:"request5", newPacket(OperationRequest, mac5, ip5, zeroMAC, routerIP), nil, 4, 1},
		{name:"request5-2", newPacket(OperationRequest, mac5, ip2, zeroMAC, routerIP), nil, 4, 2},
		{name:"request5-3", newPacket(OperationRequest, mac5, ip3, zeroMAC, routerIP), nil, 4, 3},
		{name:"announce5-4", newPacket(OperationRequest, mac5, ip4, zeroMAC, ip4), nil, 4, 4},
		{name:"probe", newPacket(OperationRequest, mac2, net.IPv4zero, zeroMAC, ip4), nil, 4, 0},                                        // probe has sIP zero
		{name:"locallink", newPacket(OperationRequest, mac2, net.IPv4(169, 254, 0, 10), zeroMAC, net.IPv4(169, 254, 0, 10)), nil, 4, 0}, // link local 169.254.x.x
		***/
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ether, err := tt.ether.AppendPayload(tt.arp)
			if err != nil {
				panic(err)
			}
			if _, err := h.client.WriteTo(ether, nil); err != tt.wantErr {
				t.Errorf("Test_Requests:%s error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
			time.Sleep(time.Millisecond * 10)
			if len(h.table.macTable) != tt.wantLen {
				t.Errorf("Test_Requests:%s table len = %v, wantLen %v", tt.name, len(h.table.macTable), tt.wantLen)
			}
			if tt.wantIPs != 0 {
				e := h.table.findByMAC(tt.arp.SrcMAC())
				if e == nil || len(e.IPs()) != tt.wantIPs {
					t.Errorf("Test_Requests:%s table IP entry=%+v, wantLen %v", tt.name, e, tt.wantLen)
				}
			}
		})
	}
	cancel()
	wg.Wait()
}

func Test_ServeReplies(t *testing.T) {
	// Debug = true
	// log.SetLevel(log.DebugLevel)
	h, conn := testHandler(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	go func() {
		wg.Add(1)
		h.ListenAndServe(ctx)
		wg.Done()
	}()

	tests := []struct {
		name    string
		packet  ARP
		wantErr error
		wantLen int
		wantIPs int
	}{
		{"replyHost", newPacket(OperationReply, hostMAC, hostIP, mac2, ip2), nil, 0, 0},
		{"replyRouter", newPacket(OperationReply, routerMAC, routerIP, mac2, ip2), nil, 0, 0},
		{"locallink", newPacket(OperationReply, mac2, net.IPv4(169, 254, 0, 10), zeroMAC, net.IPv4(169, 254, 0, 10)), nil, 0, 0}, // link local 169.254.x.x
		{"reply2", newPacket(OperationReply, mac2, ip2, routerMAC, routerIP), nil, 1, 1},
		{"reply2-2", newPacket(OperationReply, mac2, ip2, hostMAC, hostIP), nil, 1, 1},
		{"request2", newPacket(OperationRequest, mac2, ip2, zeroMAC, ip3), nil, 1, 1}, // add a request in the middle
		{"reply2-3", newPacket(OperationReply, mac2, ip2, hostMAC, hostIP), nil, 1, 1},
		{"reply2-4", newPacket(OperationReply, mac2, ip3, hostMAC, hostIP), nil, 1, 2},
		{"request3", newPacket(OperationRequest, mac3, ip3, zeroMAC, routerIP), nil, 2, 1},
		{"reply3-1", newPacket(OperationReply, mac3, ip4, hostMAC, hostIP), nil, 2, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := conn.WriteTo(tt.packet, nil); err != tt.wantErr {
				t.Errorf("Test_Requests:%s error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
			time.Sleep(time.Millisecond * 10)
			if len(h.table.macTable) != tt.wantLen {
				t.Errorf("Test_Requests:%s table len = %v, wantLen %v", tt.name, len(h.table.macTable), tt.wantLen)
			}
			if tt.wantIPs != 0 {
				e := h.table.findByMAC(tt.packet.SrcMAC())
				if e == nil || len(e.IPs()) != tt.wantIPs {
					t.Errorf("Test_Requests:%s table IP entry=%+v, wantLen %v", tt.name, e, tt.wantLen)
				}
			}
		})
	}
	cancel()
	wg.Wait()
}
func Test_CaptureSameIP(t *testing.T) {
	// Debug = true
	// log.SetLevel(log.DebugLevel)
	h, conn := testHandler(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	go func() {
		wg.Add(1)
		h.ListenAndServe(ctx)
		wg.Done()
	}()

	e, _ := h.table.upsert(StateNormal, mac2, ip2)
	e.Online = true
	time.Sleep(time.Millisecond * 20) // time for ListenAndServe to start
	h.ForceIPChange(mac2, true)

	tests := []struct {
		name      string
		packet    ARP
		wantErr   error
		wantLen   int
		wantIPs   int
		wantState arpState
	}{
		{"request5-1", newPacket(OperationRequest, mac5, ip5, zeroMAC, hostIP), nil, 3, 1, StateNormal},
		{"reply2-1", newPacket(OperationReply, mac2, ip2, zeroMAC, hostIP), nil, 3, 1, StateHunt},
		{"reply2-2", newPacket(OperationReply, mac2, ip2, zeroMAC, hostIP), nil, 3, 1, StateHunt},
		{"reply2-3", newPacket(OperationReply, mac2, ip2, hostMAC, hostIP), nil, 3, 1, StateHunt},
		{"reply2-4", newPacket(OperationReply, mac2, ip2, routerMAC, routerIP), nil, 3, 1, StateHunt},
		{"reply2-4", newPacket(OperationReply, mac2, ip2, mac3, ip3), nil, 3, 1, StateHunt},
		{"request2-1", newPacket(OperationRequest, mac2, ip2, zeroMAC, routerIP), nil, 3, 1, StateHunt},
		{"request2-2", newPacket(OperationRequest, mac2, ip2, zeroMAC, hostIP), nil, 3, 1, StateHunt},
		{"request2-4", newPacket(OperationRequest, mac2, ip2, mac3, ip3), nil, 3, 1, StateHunt},
		{"request3-1", newPacket(OperationRequest, mac2, ip3, zeroMAC, hostIP), nil, 3, 2, StateNormal},
		{"request3-2", newPacket(OperationRequest, mac2, ip2, zeroMAC, ip2), nil, 3, 2, StateNormal}, // announce old IP
		{"request4-1", newPacket(OperationRequest, mac2, ip4, zeroMAC, hostIP), nil, 3, 3, StateNormal},
		{"request5-1", newPacket(OperationRequest, mac2, ip5, zeroMAC, hostIP), nil, 3, 4, StateNormal},
		{"request3-3", newPacket(OperationRequest, mac2, ip2, zeroMAC, ip2), nil, 3, 4, StateNormal}, // announce old IP
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := conn.WriteTo(tt.packet, nil); err != tt.wantErr {
				t.Errorf("Test_catpureSameIP:%s error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
			time.Sleep(time.Millisecond * 10)
			if len(h.table.macTable) != tt.wantLen {
				h.PrintTable()
				t.Errorf("Test_catpureSameIP:%s table len = %v, wantLen %v", tt.name, len(h.table.macTable), tt.wantLen)
			}
			if tt.wantIPs != 0 {
				e := h.table.findByMAC(tt.packet.SrcMAC())
				if e == nil || len(e.IPs()) != tt.wantIPs {
					t.Errorf("Test_catpureSameIP:%s table IP entry=%+v, wantLen %v", tt.name, e, tt.wantIPs)
					h.PrintTable()
				}
				if e.State != tt.wantState {
					t.Errorf("Test_captureSameIP:%s entry state=%s, wantState %v", tt.name, e.State, tt.wantState)

				}
			}
		})
	}
	cancel()
	wg.Wait()
}

func Test_CaptureEnterOffline(t *testing.T) {
	// Debug = true
	// log.SetLevel(log.DebugLevel)
	h, conn := testHandler(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	notification := addNotification(ctx, h)

	var wg sync.WaitGroup
	go func() {
		wg.Add(1)
		h.ListenAndServe(ctx)
		wg.Done()
	}()

	e2, _ := h.table.upsert(StateNormal, mac2, ip2)
	e2.Online = true
	e3, _ := h.table.upsert(StateNormal, mac3, ip3)
	e3.Online = true
	e4, _ := h.table.upsert(StateNormal, mac4, ip4)
	e4.Online = true
	time.Sleep(time.Millisecond * 20) // time for ListenAndServe to start
	h.ForceIPChange(mac2, true)
	time.Sleep(time.Millisecond * 20)
	if e := h.table.findByMAC(mac2); e == nil || e.State != StateHunt || !e.Online {
		t.Fatalf("Test_CaptureEnterOffline entry2 state=%s, online=%v", e.State, e.Online)
	}
	if e := h.table.findVirtualIP(ip2); e == nil || e.State != StateVirtualHost || !e.Online {
		h.PrintTable()
		t.Fatalf("Test_CaptureEnterOffline wrong virtualip entry=%v", e)
	}
	if e := h.table.findByMAC(mac3); e == nil || e.State != StateNormal || !e.Online {
		t.Fatalf("Test_CaptureEnterOffline entry3 state=%s, online=%v", e.State, e.Online)
	}
	if e := h.table.findByMAC(mac4); e == nil || e.State != StateNormal || !e.Online {
		t.Fatalf("Test_CaptureEnterOffline entry4 state=%s, online=%v", e.State, e.Online)
	}

	time.Sleep(h.config.ProbeInterval / 2)

	tests := []struct {
		name      string
		packet    ARP
		wantErr   error
		wantLen   int
		wantIPs   int
		wantState arpState
	}{
		{"reply3-1", newPacket(OperationReply, mac3, ip3, zeroMAC, hostIP), nil, 4, 1, StateNormal},
		{"reply4-1", newPacket(OperationReply, mac4, ip4, zeroMAC, hostIP), nil, 4, 1, StateNormal},
		{"reply5-1", newPacket(OperationReply, mac5, ip5, zeroMAC, hostIP), nil, 5, 1, StateNormal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := conn.WriteTo(tt.packet, nil); err != tt.wantErr {
				t.Errorf("Test_Capture:%s error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
			time.Sleep(time.Millisecond * 10)
			if len(h.table.macTable) != tt.wantLen {
				t.Errorf("Test_Capture:%s table len = %v, wantLen %v", tt.name, len(h.table.macTable), tt.wantLen)
			}
			if tt.wantIPs != 0 {
				e := h.table.findByMAC(tt.packet.SrcMAC())
				if e == nil || len(e.IPs()) != tt.wantIPs {
					t.Errorf("Test_Capture:%s table IP len=%+v, wantLen %v", tt.name, len(e.IPs()), tt.wantIPs)
				}
				if e.State != tt.wantState {
					t.Errorf("Test_Capture:%s entry state=%s, wantState %v", tt.name, e.State, tt.wantState)

				}
			}
		})
	}

	// wait until offline
	time.Sleep(h.config.OfflineDeadline)

	h.Lock()
	if e := h.table.findByMAC(mac2); e == nil || e.State != StateNormal || e.Online {
		t.Fatalf("Test_CaptureEnterOffline is not normal entry=%+v", e)
	}
	if e := h.table.findVirtualIP(ip2); e == nil || e.State != StateVirtualHost || !e.Online {
		t.Fatalf("Test_CaptureEnterOffline wrong virtualip entry=%v", e)
	}
	h.Unlock()

	// wait until purge
	time.Sleep(h.config.PurgeDeadline - h.config.OfflineDeadline)

	h.Lock()
	if e := h.table.findByMAC(mac2); e != nil {
		t.Fatalf("Test_CaptureEnterOffline is not offline entry=%+v", e)
	}
	if e := h.table.findVirtualIP(ip2); e == nil || e.State != StateVirtualHost || e.Online {
		t.Fatalf("Test_CaptureEnterOffline wrong virtualip entry=%v", e)
	}
	h.Unlock()

	cancel()
	wg.Wait()

	log.Printf("notification %+v", notification)
}
