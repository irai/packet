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

	ctx, cancel := context.WithCancel(context.Background())

	// setup packet handler
	config := packet.Config{
		ProbeInterval:           time.Minute * 1,
		FullNetworkScanInterval: time.Minute * 20,
		PurgeDeadline:           time.Minute * 10}
	// setup packet listener
	engine, err := config.New(*nic)
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
	defer engine.Close()
	fmt.Println("nic info  :", engine.NICInfo)

	// ARP
	arpHandler, err := arp.Open(engine)
	if err != nil {
		log.Fatalf("Failed to create arp handler nic=%s handler: %s", *nic, err)
	}

	// ICMPv4
	h4, err := icmp4.Open(engine)
	if err != nil {
		log.Fatalf("Failed to create icmp nic=%s handler: %s", *nic, err)
	}
	defer h4.Close()

	// ICMPv6
	h6, err := icmp6.New(engine)
	if err != nil {
		log.Fatalf("Failed to create icmp6 nic=%s handler: %s", *nic, err)
	}
	defer h6.Close()

	engine.AddCallback(func(n packet.Notification) error {
		fmt.Println("Got notification : ", n)
		return nil
	})

	// Start server listener
	go func() {
		if err := engine.ListenAndServe(ctx); err != nil {
			if ctx.Err() != context.Canceled {
				panic(err)
			}
		}
	}()

	time.Sleep(time.Millisecond * 10) // time for all goroutine to start

	cmd(engine, arpHandler, h4, h6)

	cancel()
}

func cmd(pt *packet.Handler, a4 *arp.Handler, h *icmp4.Handler, h6 *icmp6.Handler) {

	radvs, _ := h6.StartRADVS(false, false, icmp6.MyHomePrefix, icmp6.RDNSSCLoudflare)
	defer radvs.Stop()

	for {
		fmt.Println("Command: (q)uit            | (p)ing ip | (l)list | (g) loG <level>")
		fmt.Println(" packet: (hunt) mac        | (release) mac")
		fmt.Println("  icmp6: (icmp6hunt) mac   | (icmp6release) mac ")
		fmt.Println("    ndp: (ra) ip6          | (ns) ip6")
		fmt.Println("    arp: (arphunt) mac     | (arprelease) mac        | (arpscan) ")
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
				if err := h.SendEchoRequest(packet.Addr{MAC: packet.Eth4AllNodesMulticast, IP: ip}, 2, 2); err != nil {
					fmt.Println("ping error ", err)
					continue
				}
				fmt.Printf("ping %v time=%v\n", dstIP, time.Now().Sub(now))
			}
			if packet.IsIP6(ip) {
				if err := h6.SendEchoRequest(packet.Addr{MAC: packet.Eth6AllNodesMulticast, IP: ip}, 1, 2); err != nil {
					// if err := h6.Ping(h6.LLA().IP, ip, time.Second*2); err != nil {
					fmt.Println("icmp6 echo error ", err)
					continue
				}
				fmt.Printf("ping %v time=%v\n", dstIP, time.Now().Sub(now))
			}
		case "ns":
			ip := getIP(tokens, 1)
			if ip == nil || !packet.IsIP6(ip) {
				continue
			}
			if err := h6.SendNeighbourSolicitation(ip); err != nil {
				fmt.Printf("error in neigbour solicitation: %s\n", err)
			}
		case "ra":
			if err := radvs.SendRA(); err != nil {
				fmt.Printf("error in router adversitement: %s\n", err)
			}
		case "arphunt":
			if mac := getMAC(tokens, 1); mac != nil {
				if err := a4.StartHunt(mac); err != nil {
					fmt.Println("error in start hunt ", err)
				}
			}
		case "arprelease":
			if mac := getMAC(tokens, 1); mac != nil {
				if err := a4.StopHunt(mac); err != nil {
					fmt.Println("error in start hunt ", err)
				}
			}
		case "arpscan":
			if err := a4.ScanNetwork(context.Background(), pt.NICInfo.HostIP4); err != nil {
				fmt.Println("failed scan: ", err)
			}
		case "icmp6hunt":
			if mac := getMAC(tokens, 1); mac != nil {
				if err := h6.StartHunt(mac); err != nil {
					fmt.Println("error in start hunt ", err)
				}
			}
		case "icmp6release":
			if mac := getMAC(tokens, 1); mac != nil {
				if err := h6.StopHunt(mac); err != nil {
					fmt.Println("error in start hunt ", err)
				}
			}
		case "hunt":
			if mac := getMAC(tokens, 1); mac != nil {
				if err := pt.StartHunt(mac); err != nil {
					fmt.Println("error in start hunt ", err)
				}
			}
		case "release":
			if mac := getMAC(tokens, 1); mac != nil {
				if err := pt.StopHunt(mac); err != nil {
					fmt.Println("error in start hunt ", err)
				}
			}
		}
	}
}
