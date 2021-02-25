package arp

import (
	"context"
	"fmt"
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
	buf := make([]byte, raw.EthMaxSize) // allocate in the stack
	p := raw.EtherMarshalBinary(buf, hType, srcMAC, dstMAC)
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
					log.Print("got notification online", entry.String(), n.onlineCounter)
				} else {
					n.offlineCounter++
					log.Print("got notification offline", entry.String(), n.offlineCounter)
				}
			}
		}
	}()

	return n
}

type testContext struct {
	inConn  net.PacketConn
	outConn net.PacketConn
	arp     *Handler
	packet  *packet.Handler
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc
}

func setupTestHandler(t *testing.T) *testContext {

	var err error

	tc := testContext{}
	tc.inConn, tc.outConn = raw.NewBufferedConn()
	tc.ctx, tc.cancel = context.WithCancel(context.Background())

	// MUST read the out conn to avoid blocking the sender
	go func() {
		buf := make([]byte, 2000)
		for {
			n, _, err := tc.outConn.ReadFrom(buf)
			if err != nil {
				if tc.ctx.Err() != context.Canceled {
					panic(err)
				}
			}
			if tc.ctx.Err() == context.Canceled {
				return
			}
			buf = buf[:n]
			ether := raw.Ether(buf)
			arp := ARP(ether.Payload())
			if !ether.IsValid() {
				s := fmt.Sprintf("error ether client packet %s", ether)
				panic(s)
			}
			if !arp.IsValid() {
				s := fmt.Sprintf("error arp client packet %s %s", ether, arp)
				panic(s)
			}
			// fmt.Println("read client packet", raw.Ether(buf), ARP(raw.Ether(buf).Payload()))
		}
	}()

	// setup server with server conn
	tc.packet, err = packet.Config{Conn: tc.inConn}.New("eth0")
	if err != nil {
		all, _ := net.Interfaces()
		fmt.Println("valid interfaces")
		for _, v := range all {
			fmt.Printf("%s: %+v\n", v.Name, v)
		}
		panic(err)
	}

	arpConfig := Config{
		HostMAC:  hostMAC,
		HostIP:   hostIP,
		RouterIP: routerIP, HomeLAN: homeLAN,
		FullNetworkScanInterval: time.Second * 60,
		ProbeInterval:           time.Second * 1,
		OfflineDeadline:         time.Second * 2,
		PurgeDeadline:           time.Second * 4,
	}
	tc.arp, err = New(tc.inConn, tc.packet.LANHosts, arpConfig)
	tc.arp.table = newARPTable() // we want an empty table
	tc.packet.ARP = tc.arp

	go func() {
		if err := tc.packet.ListenAndServe(tc.ctx); err != nil {
			panic(err)
		}
	}()

	time.Sleep(time.Millisecond * 10) // time for all goroutine to start
	return &tc
}

func (tc *testContext) Close() {
	time.Sleep(time.Millisecond * 20) // wait for all packets to finish
	fmt.Println("teminating context")
	tc.cancel()
	tc.wg.Wait()
}

func Test_Handler_ARPRequests(t *testing.T) {
	//Debug = true
	// log.SetLevel(log.DebugLevel)
	tc := setupTestHandler(t)
	defer tc.Close()

	packet.Debug = true

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
			// fmt.Println("frame ether: ", ether, "frame arp: ", ARP(ether.Payload()), "srcarp: ", tt.arp)
			if _, err := tc.outConn.WriteTo(ether, nil); err != tt.wantErr {
				t.Errorf("Test_Requests:%s error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
			time.Sleep(time.Millisecond * 10)

			tc.arp.Lock()
			defer tc.arp.Unlock()

			if len(tc.arp.table.macTable) != tt.wantLen {
				tc.arp.printTable()
				t.Errorf("Test_Requests:%s table len = %v, wantLen %v", tt.name, len(tc.arp.table.macTable), tt.wantLen)
			}
			if tt.wantIPs != 0 {
				e := tc.arp.table.findByMAC(tt.arp.SrcMAC())
				if e == nil || len(e.IPs()) != tt.wantIPs {
					t.Errorf("Test_Requests:%s table IP entry=%+v, wantLen %v", tt.name, e, tt.wantLen)
				}
			}
		})
	}
}

func Test_Handler_ServeReplies(t *testing.T) {
	// Debug = true
	// log.SetLevel(log.DebugLevel)
	tc := setupTestHandler(t)
	defer tc.Close()
	packet.Debug = true

	tests := []struct {
		name    string
		ether   raw.Ether
		arp     ARP
		wantErr error
		wantLen int
		wantIPs int
	}{
		{name: "replyHost",
			ether:   newEtherPacket(syscall.ETH_P_ARP, hostMAC, mac2),
			arp:     newPacket(OperationReply, hostMAC, hostIP, mac2, ip2),
			wantErr: nil, wantLen: 0, wantIPs: 0},
		{name: "replyRouter",
			ether:   newEtherPacket(syscall.ETH_P_ARP, routerMAC, EthernetBroadcast),
			arp:     newPacket(OperationReply, routerMAC, routerIP, mac2, ip2),
			wantErr: nil, wantLen: 0, wantIPs: 0},
		{name: "replyLocalLink",
			ether:   newEtherPacket(syscall.ETH_P_ARP, routerMAC, EthernetBroadcast),
			arp:     newPacket(OperationReply, mac2, localIP, zeroMAC, localIP),
			wantErr: nil, wantLen: 0, wantIPs: 0},
		{name: "replyMAC2",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, mac1),
			arp:     newPacket(OperationReply, mac2, ip2, routerMAC, routerIP),
			wantErr: nil, wantLen: 1, wantIPs: 1},
		{name: "replyMAC2-dup",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, mac1),
			arp:     newPacket(OperationReply, mac2, ip2, routerMAC, routerIP),
			wantErr: nil, wantLen: 1, wantIPs: 1},
		{name: "requestMAC2",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, hostMAC),
			arp:     newPacket(OperationRequest, mac2, ip2, hostMAC, hostIP),
			wantErr: nil, wantLen: 1, wantIPs: 1},
		{name: "replyMAC2-dup2",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, hostMAC),
			arp:     newPacket(OperationReply, mac2, ip2, hostMAC, hostIP),
			wantErr: nil, wantLen: 1, wantIPs: 1},
		{name: "replyMAC2-newip",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, hostMAC),
			arp:     newPacket(OperationReply, mac2, ip3, hostMAC, hostIP),
			wantErr: nil, wantLen: 1, wantIPs: 2},
		{name: "requestMAC3-newip",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac3, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac3, ip3, hostMAC, hostIP),
			wantErr: nil, wantLen: 2, wantIPs: 1},
		{name: "replyMAC3",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac3, hostMAC),
			arp:     newPacket(OperationReply, mac3, ip4, hostMAC, hostIP),
			wantErr: nil, wantLen: 2, wantIPs: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ether, err := tt.ether.AppendPayload(tt.arp)
			if err != nil {
				panic(err)
			}
			if _, err := tc.outConn.WriteTo(ether, nil); err != tt.wantErr {
				t.Errorf("Test_Requests:%s error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
			time.Sleep(time.Millisecond * 10)

			tc.arp.Lock()
			defer tc.arp.Unlock()

			if len(tc.arp.table.macTable) != tt.wantLen {
				t.Errorf("Test_Requests:%s table len = %v, wantLen %v", tt.name, len(tc.arp.table.macTable), tt.wantLen)
			}
			if tt.wantIPs != 0 {
				e := tc.arp.table.findByMAC(tt.arp.SrcMAC())
				if e == nil || len(e.IPs()) != tt.wantIPs {
					t.Errorf("Test_Requests:%s table IP entry=%+v, wantLen %v", tt.name, e, tt.wantLen)
				}
			}
		})
	}
}
func Test_Handler_CaptureSameIP(t *testing.T) {
	Debug = true
	tc := setupTestHandler(t)
	defer tc.Close()

	packet.Debug = true

	e, _ := tc.arp.table.upsert(StateNormal, mac2, ip2)
	e.Online = true
	tc.arp.ForceIPChange(mac2, true)

	tests := []struct {
		name      string
		ether     raw.Ether
		arp       ARP
		wantErr   error
		wantLen   int
		wantIPs   int
		wantState arpState
	}{
		{name: "requestMAC5",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac5, hostMAC),
			arp:     newPacket(OperationRequest, mac5, ip5, zeroMAC, hostIP),
			wantErr: nil, wantLen: 3, wantIPs: 1, wantState: StateNormal},
		{name: "replyMAC2-1",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, hostMAC),
			arp:     newPacket(OperationReply, mac2, ip2, zeroMAC, hostIP),
			wantErr: nil, wantLen: 3, wantIPs: 1, wantState: StateHunt},
		{name: "replyMAC2-2",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, hostMAC),
			arp:     newPacket(OperationReply, mac2, ip2, zeroMAC, hostIP),
			wantErr: nil, wantLen: 3, wantIPs: 1, wantState: StateHunt},
		{name: "replyMAC2-3",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, hostMAC),
			arp:     newPacket(OperationReply, mac2, ip2, zeroMAC, hostIP),
			wantErr: nil, wantLen: 3, wantIPs: 1, wantState: StateHunt},
		{name: "replyMAC2-4",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, routerMAC),
			arp:     newPacket(OperationReply, mac2, ip2, routerMAC, routerIP),
			wantErr: nil, wantLen: 3, wantIPs: 1, wantState: StateHunt},
		{name: "replyMAC2-5",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, mac3),
			arp:     newPacket(OperationReply, mac2, ip2, mac3, ip3),
			wantErr: nil, wantLen: 3, wantIPs: 1, wantState: StateHunt},
		{name: "requestMAC2-1",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, routerMAC),
			arp:     newPacket(OperationRequest, mac2, ip2, zeroMAC, routerIP),
			wantErr: nil, wantLen: 3, wantIPs: 1, wantState: StateHunt},
		{name: "requestMAC2-2",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, hostMAC),
			arp:     newPacket(OperationRequest, mac2, ip2, hostMAC, hostIP),
			wantErr: nil, wantLen: 3, wantIPs: 1, wantState: StateHunt},
		{name: "requestMAC2-3",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, mac3),
			arp:     newPacket(OperationRequest, mac2, ip2, mac3, ip3),
			wantErr: nil, wantLen: 3, wantIPs: 1, wantState: StateHunt},
		{name: "announce new IP3",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac2, ip3, zeroMAC, hostIP),
			wantErr: nil, wantLen: 3, wantIPs: 2, wantState: StateNormal},
		{name: "announce old IP2",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac2, ip2, zeroMAC, ip2),
			wantErr: nil, wantLen: 3, wantIPs: 2, wantState: StateNormal},
		{name: "announce new IP4",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, hostMAC),
			arp:     newPacket(OperationRequest, mac2, ip4, zeroMAC, ip4),
			wantErr: nil, wantLen: 3, wantIPs: 3, wantState: StateNormal},
		{name: "announce new IP5",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac2, ip5, zeroMAC, ip5),
			wantErr: nil, wantLen: 3, wantIPs: 4, wantState: StateNormal},
		{name: "announce old IP2-2",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac2, EthernetBroadcast),
			arp:     newPacket(OperationRequest, mac2, ip2, zeroMAC, ip2),
			wantErr: nil, wantLen: 3, wantIPs: 4, wantState: StateNormal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ether, err := tt.ether.AppendPayload(tt.arp)
			if err != nil {
				panic(err)
			}
			if _, err := tc.outConn.WriteTo(ether, nil); err != tt.wantErr {
				t.Errorf("Test_catpureSameIP:%s error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
			fmt.Println("writing finished")
			time.Sleep(time.Millisecond * 10)

			tc.arp.Lock()
			defer tc.arp.Unlock()

			if len(tc.arp.table.macTable) != tt.wantLen {
				tc.arp.PrintTable()
				t.Errorf("Test_catpureSameIP:%s table len = %v, wantLen %v", tt.name, len(tc.arp.table.macTable), tt.wantLen)
			}
			if tt.wantIPs != 0 {
				e := tc.arp.table.findByMAC(tt.arp.SrcMAC())
				if e == nil || len(e.IPs()) != tt.wantIPs {
					t.Errorf("Test_catpureSameIP:%s table IP entry=%+v, wantLen %v", tt.name, e, tt.wantIPs)
					tc.arp.PrintTable()
				}
				if e.State != tt.wantState {
					t.Errorf("Test_captureSameIP:%s entry state=%s, wantState %v", tt.name, e.State, tt.wantState)

				}
			}
		})
	}
}

func Test_Handler_CaptureEnterOffline(t *testing.T) {
	// Debug = true
	// log.SetLevel(log.DebugLevel)
	tc := setupTestHandler(t)
	defer tc.Close()

	packet.Debug = true

	notification := addNotification(tc.ctx, tc.arp)

	e2, _ := tc.arp.table.upsert(StateNormal, mac2, ip2)
	e2.Online = true
	e3, _ := tc.arp.table.upsert(StateNormal, mac3, ip3)
	e3.Online = true
	e4, _ := tc.arp.table.upsert(StateNormal, mac4, ip4)
	e4.Online = true
	tc.arp.ForceIPChange(mac2, true)
	time.Sleep(time.Millisecond * 20)

	tc.arp.Lock()
	if e := tc.arp.table.findByMAC(mac2); e == nil || e.State != StateHunt || !e.Online {
		t.Fatalf("Test_CaptureEnterOffline entry2 state=%s, online=%v", e.State, e.Online)
	}
	if e := tc.arp.table.findVirtualIP(ip2); e == nil || e.State != StateVirtualHost || !e.Online {
		tc.arp.PrintTable()
		t.Fatalf("Test_CaptureEnterOffline wrong virtualip entry=%v", e)
	}
	if e := tc.arp.table.findByMAC(mac3); e == nil || e.State != StateNormal || !e.Online {
		t.Fatalf("Test_CaptureEnterOffline entry3 state=%s, online=%v", e.State, e.Online)
	}
	if e := tc.arp.table.findByMAC(mac4); e == nil || e.State != StateNormal || !e.Online {
		t.Fatalf("Test_CaptureEnterOffline entry4 state=%s, online=%v", e.State, e.Online)
	}
	tc.arp.Unlock()

	time.Sleep(tc.arp.config.ProbeInterval / 2)

	tests := []struct {
		name      string
		ether     raw.Ether
		arp       ARP
		wantErr   error
		wantLen   int
		wantIPs   int
		wantState arpState
	}{
		{name: "replyMAC3",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac3, EthernetBroadcast),
			arp:     newPacket(OperationReply, mac3, ip3, zeroMAC, hostIP),
			wantErr: nil, wantLen: 4, wantIPs: 1, wantState: StateNormal},
		{name: "replyMAC4",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac4, EthernetBroadcast),
			arp:     newPacket(OperationReply, mac4, ip4, zeroMAC, hostIP),
			wantErr: nil, wantLen: 4, wantIPs: 1, wantState: StateNormal},
		{name: "replyMAC5",
			ether:   newEtherPacket(syscall.ETH_P_ARP, mac5, EthernetBroadcast),
			arp:     newPacket(OperationReply, mac5, ip5, zeroMAC, hostIP),
			wantErr: nil, wantLen: 5, wantIPs: 1, wantState: StateNormal},
		// {"reply3-1", newPacket(OperationReply, mac3, ip3, zeroMAC, hostIP), nil, 4, 1, StateNormal},
		// {"reply4-1", newPacket(OperationReply, mac4, ip4, zeroMAC, hostIP), nil, 4, 1, StateNormal},
		// {"reply5-1", newPacket(OperationReply, mac5, ip5, zeroMAC, hostIP), nil, 5, 1, StateNormal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ether, err := tt.ether.AppendPayload(tt.arp)
			if err != nil {
				panic(err)
			}
			if _, err := tc.outConn.WriteTo(ether, nil); err != tt.wantErr {
				t.Errorf("Test_Capture:%s error = %v, wantErr %v", tt.name, err, tt.wantErr)
			}
			time.Sleep(time.Millisecond * 10)

			tc.arp.Lock()
			defer tc.arp.Unlock()

			if len(tc.arp.table.macTable) != tt.wantLen {
				t.Errorf("Test_Capture:%s table len = %v, wantLen %v", tt.name, len(tc.arp.table.macTable), tt.wantLen)
			}
			if tt.wantIPs != 0 {
				e := tc.arp.table.findByMAC(tt.arp.SrcMAC())
				if e == nil || len(e.IPs()) != tt.wantIPs {
					t.Fatalf("Test_Capture:%s table IP entry=%+v, wantLen %v", tt.name, e, tt.wantIPs)
				}
				if e.State != tt.wantState {
					t.Errorf("Test_Capture:%s entry state=%s, wantState %v", tt.name, e.State, tt.wantState)

				}
			}
		})
	}

	// wait until offline
	time.Sleep(tc.arp.config.OfflineDeadline + time.Second)

	tc.arp.Lock()
	if e := tc.arp.table.findByMAC(mac2); e == nil || e.State != StateNormal || e.Online {
		t.Fatalf("Test_CaptureEnterOffline is not normal entry=%+v", e)
	}
	if e := tc.arp.table.findVirtualIP(ip2); e == nil || e.State != StateVirtualHost || !e.Online {
		t.Fatalf("Test_CaptureEnterOffline wrong virtualip entry=%v", e)
	}
	tc.arp.Unlock()

	// wait until purge
	time.Sleep(tc.arp.config.PurgeDeadline - tc.arp.config.OfflineDeadline)

	tc.arp.Lock()
	if e := tc.arp.table.findByMAC(mac2); e != nil {
		t.Fatalf("Test_CaptureEnterOffline is not offline entry=%+v", e)
	}
	if e := tc.arp.table.findVirtualIP(ip2); e == nil || e.State != StateVirtualHost || e.Online {
		tc.arp.printTable()
		t.Fatalf("Test_CaptureEnterOffline wrong virtualip entry=%v", e)
	}
	tc.arp.Unlock()

	log.Printf("notification %+v", notification)
}
