package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
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
	fmt.Printf("Using nic %v src=%v dst=%v\n", *nic, *srcIP, *dstIP)

	mac, ipNet4, lla, gua, err := raw.GetNICInfo(*nic)
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
	fmt.Println("mac : ", mac)
	fmt.Println("ip4 : ", ipNet4)
	fmt.Println("lla : ", lla)
	fmt.Println("gua : ", gua)

	ctx, cancel := context.WithCancel(context.Background())

	// setup packet listener
	packet, err := packet.New(*nic)
	if err != nil {
		panic(err)
	}
	defer packet.Close()

	// setup ARP handler
	homeLAN := net.IPNet{IP: ipNet4.IP.Mask(ipNet4.Mask), Mask: ipNet4.Mask}
	arpHandler, err := arp.New(packet.Conn(), packet.LANHosts, arp.Config{HostMAC: mac, HostIP: ipNet4.IP, HomeLAN: homeLAN})
	packet.ARP = arpHandler

	// ICMPv4
	h4, err := icmp4.New(packet.Interface(), packet.Conn(), packet.LANHosts, ipNet4.IP)
	if err != nil {
		log.Fatalf("Failed to create icmp nic=%s handler: ", *nic, err)
	}
	defer h4.Close()
	packet.ICMP4Hook("icmp4", h4)

	// ICMPv6
	icmp6Config := icmp6.Config{GlobalUnicastAddress: gua, LocalLinkAddress: lla}
	h6, err := icmp6.New(packet.Interface(), packet.Conn(), packet.LANHosts, icmp6Config)
	if err != nil {
		log.Fatalf("Failed to create icmp6 nic=%s handler: ", *nic, err)
	}
	defer h6.Close()
	packet.ICMP6Hook("icmp6", h6)

	// Start server listener
	go func() {
		if err := packet.ListenAndServe(ctx); err != nil {
			if ctx.Err() != context.Canceled {
				panic(err)
			}
		}
	}()

	time.Sleep(time.Millisecond * 10) // time for all goroutine to start

	cmd(packet, h4, h6)

	cancel()
}

func cmd(pt *packet.Handler, h *icmp4.Handler, h6 *icmp6.Handler) {

	radvs, _ := h6.StartRADVS(false, false, icmp6.MyHomePrefix, icmp6.RDNSSCLoudflare)
	defer radvs.Stop()

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println("Command: (q)uit            | (p)ing ip | (l)list | (g) loG <level>")
		fmt.Println("    ndp: (ra) ip6          | (ns) ip6")
		fmt.Print("Enter command: ")
		text, _ := reader.ReadString('\n')
		text = strings.ToLower(text[:len(text)-1])

		// handle windows line feed
		if len(text) > 1 && text[len(text)-1] == '\r' {
			text = strings.ToLower(text[:len(text)-1])
		}

		if text == "" {
			continue
		}
		tokens := strings.Split(text, " ")

		switch tokens[0] {
		case "q":
			return
		case "l":
			pt.PrintTable()
			h6.PrintTable()

		case "g":
			if icmp4.Debug {
				fmt.Printf("Debugging is OFF\n")
				icmp4.Debug = false
				packet.Debug = false
				icmp6.Debug = false
				arp.Debug = false
			} else {
				fmt.Printf("Debugging is ON\n")
				icmp4.Debug = true
				packet.Debug = true
				icmp6.Debug = true
				arp.Debug = true
			}
		case "p":
			if len(tokens) < 2 {
				fmt.Println("missing ip")
				continue
			}
			ip := net.ParseIP(tokens[1])
			if ip == nil || ip.IsUnspecified() {
				fmt.Println("invalid ip=", ip)
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
			if ip.To16() != nil && ip.To4() == nil {
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
		}
	}
}

func getIP(tokens []string, pos int) net.IP {
	if len(tokens) < pos+1 {
		fmt.Println("missing ip", tokens)
		return nil
	}
	ip := net.ParseIP(tokens[pos])
	if ip == nil || ip.IsUnspecified() {
		fmt.Println("invalid ip=", ip)
		return nil
	}
	return ip
}
