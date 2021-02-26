package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/irai/packet"
	"github.com/irai/packet/arp"
	"github.com/irai/packet/icmp4"
	"github.com/irai/packet/icmp6"
	"github.com/irai/packet/raw"
)

var (
	srcIP = flag.String("src", "192.168.0.5", "source IP for originating packet")
	dstIP = flag.String("dst", "192.168.0.1", "destination IP for target packet")
	nic   = flag.String("nic", "eth0", "nic interface to listent to")
)

func main() {
	flag.Parse()

	icmp4.Debug = false
	log.SetLevel(log.DebugLevel)

	fmt.Printf("icmpListener: Listen and send icmp messages\n")
	fmt.Printf("Using nic %v \n", *nic)

	defaultGW, err := raw.GetLinuxDefaultGateway()
	if err != nil {
		log.Println("failed to get default gw:", err)
		defaultGW = net.IPv4(192, 168, 1, 1)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// setup packet listener
	pkt, err := packet.New(*nic)
	if err != nil {
		fmt.Printf("error opening nic=%s: %s\n", *nic, err)
		iif, _ := net.Interfaces()
		fmt.Printf("available interfaces\n")
		for _, v := range iif {
			addrs, _ := v.Addrs()
			fmt.Printf("  name=%s mac=%s\n", v.Name, v.HardwareAddr)
			for _, v := range addrs {
				fmt.Printf("    ip=%s\n", v)
			}
		}
		return
	}
	defer pkt.Close()

	fmt.Println("mac  :", pkt.HostMAC)
	fmt.Println("ip4  :", pkt.HostIP4)
	fmt.Println("gw4  :", defaultGW)
	fmt.Println("lla  :", pkt.HostLLA)
	fmt.Println("gua  :", pkt.HostGUA)
	pkt.AddCallback(func(n packet.Notification) error {
		fmt.Println("Got notification : ", n)
		return nil
	})

	// setup ARP handler
	// setup ARP handler
	homeLAN := net.IPNet{IP: pkt.HostIP4.IP.Mask(pkt.HostIP4.Mask), Mask: pkt.HostIP4.Mask}
	arpConfig := arp.Config{
		HostMAC:  pkt.HostMAC,
		HostIP:   pkt.HostIP4.IP,
		RouterIP: defaultGW, HomeLAN: homeLAN,
		ProbeInterval:           time.Minute * 1,
		FullNetworkScanInterval: time.Minute * 20,
		PurgeDeadline:           time.Minute * 10}
	arpHandler, err := arp.New(pkt.Conn(), pkt.LANHosts, arpConfig)
	pkt.ARP = arpHandler

	// ICMPv4
	h4, err := icmp4.New(pkt.Interface(), pkt.Conn(), pkt.LANHosts, pkt.HostIP4.IP)
	if err != nil {
		log.Fatalf("Failed to create icmp nic=%s handler: ", *nic, err)
	}
	defer h4.Close()
	pkt.ICMP4Hook("icmp4", h4)

	// ICMPv6
	icmp6Config := icmp6.Config{GlobalUnicastAddress: pkt.HostGUA, LocalLinkAddress: pkt.HostLLA}
	h6, err := icmp6.New(pkt.Interface(), pkt.Conn(), pkt.LANHosts, icmp6Config)
	if err != nil {
		log.Fatalf("Failed to create icmp6 nic=%s handler: ", *nic, err)
	}
	defer h6.Close()
	pkt.ICMP6Hook("icmp6", h6)

	// Start server listener
	go func() {
		if err := pkt.ListenAndServe(ctx); err != nil {
			if ctx.Err() != context.Canceled {
				panic(err)
			}
		}
	}()

	time.Sleep(time.Millisecond * 10) // time for all goroutine to start

	cmd(pkt, arpHandler, h4, h6)

	cancel()
}

func cmd(pt *packet.Handler, a4 *arp.Handler, h *icmp4.Handler, h6 *icmp6.Handler) {

	radvs, _ := h6.StartRADVS(false, false, icmp6.MyHomePrefix, icmp6.RDNSSCLoudflare)
	defer radvs.Stop()

	for {
		fmt.Println("Command: (q)uit            | (p)ing ip | (l)list | (g) loG <level>")
		fmt.Println("    ndp: (ra) ip6          | (ns) ip6")
		fmt.Println("    arp: (af)orce mac      | (as)stop mac")
		fmt.Print("Enter command: ")
		tokens := readInput()

		switch tokens[0] {
		case "q":
			return
		case "l":
			pt.PrintTable()
			h6.PrintTable()
			a4.PrintTable()

		case "g":
			p := getString(tokens, 1)
			switch p {
			case "ip4":
				packet.DebugIP4 = !packet.DebugIP4
			case "icmp4":
				icmp4.Debug = !icmp4.Debug
			case "ip6":
				packet.DebugIP6 = !packet.DebugIP6
			case "icmp6":
				icmp6.Debug = !icmp6.Debug
			case "packet":
				packet.Debug = !packet.Debug
			case "arp":
				arp.Debug = !arp.Debug
			default:
				fmt.Println("invalid package - use 'g icmp4|icmp6|arp|packet'")
			}
			fmt.Println("ip4 debug  :", packet.DebugIP4)
			fmt.Println("icmp4 debug:", icmp4.Debug)
			fmt.Println("ip6 debug  :", packet.DebugIP6)
			fmt.Println("icmp6 debug:", icmp6.Debug)
			fmt.Println("packet debug:", packet.Debug)
			fmt.Println("arp debug:", arp.Debug)
		case "p":
			ip := getIP(tokens, 1)
			if ip == nil {
				continue
			}
			now := time.Now()
			if ip.To4() != nil {
				if err := h.Ping(h.HostIP, ip, time.Second*4); err != nil {
					fmt.Println("ping error ", err)
					continue
				}
				fmt.Printf("ping %v time=%v\n", dstIP, time.Now().Sub(now))
			}
			if raw.IsIP6(ip) {
				if err := h6.SendEchoRequest(raw.Addr{MAC: icmp6.EthAllNodesMulticast, IP: ip}, 1, 2); err != nil {
					// if err := h6.Ping(h6.LLA().IP, ip, time.Second*2); err != nil {
					fmt.Println("icmp6 echo error ", err)
					continue
				}
				fmt.Printf("ping %v time=%v\n", dstIP, time.Now().Sub(now))
			}
		case "ns":
			ip := getIP(tokens, 1)
			if ip == nil || !raw.IsIP6(ip) {
				continue
			}
			if err := h6.SendNeighbourSolicitation(ip); err != nil {
				fmt.Printf("error in neigbour solicitation: %s\n", err)
			}
		case "ra":
			if err := radvs.SendRA(); err != nil {
				fmt.Printf("error in router adversitement: %s\n", err)
			}
		case "af":
			mac := getMAC(tokens, 1)
			if mac == nil {
				continue
			}
			a4.StartSpoofMAC(mac)
		case "as":
			mac := getMAC(tokens, 1)
			if mac == nil {
				continue
			}
			a4.StopSpoofMAC(mac)

		}
	}
}
