package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/arp"
	"github.com/irai/packet/dhcp4"
	"github.com/irai/packet/dns"
	"github.com/irai/packet/engine"
	"github.com/irai/packet/icmp"
	"github.com/pkg/profile"
)

var (
	dstIP = flag.String("dst", "192.168.0.1", "destination IP for target packet")
	nic   = flag.String("nic", "eth0", "nic interface to listen")
	pprof = flag.String("pprof", "", "pprof profile <cpu or mutex or block>")
)

type handlers struct {
	engine      *engine.Handler
	arp         *arp.Handler
	icmp4       *icmp.Handler4
	icmp6       *icmp.Handler6
	dhcp4       *dhcp4.Handler
	radvs       *icmp.RADVS
	netfilterIP net.IPNet
}

func main() {
	// defer profile.Start(profile.BlockProfile).Stop()

	flag.Parse()

	switch *pprof {
	case "cpu":
		defer profile.Start(profile.CPUProfile).Stop()
	case "block":
		defer profile.Start(profile.BlockProfile).Stop()
	case "goroutine":
		defer profile.Start(profile.GoroutineProfile).Stop()
	case "mutex":
		defer profile.Start(profile.MutexProfile).Stop()
	}
	// 		go tool pprof -http=:8080 http://localhost:6060/debug/pprof/mutex
	//      go tool pprof -http=:8080 http://localhost:6060/debug/pprof/block
	//      go tool pprof -http=:8080 http://localhost:6060/debug/pprof/heap
	//      go tool pprof -http=:8080 http://localhost:6060/debug/pprof/profile
	//      go tool pprof -http=:8080 http://localhost:6060/debug/pprof/goroutine

	// to open netfilter firewall for testing:
	//   sudo nft add element ip netfilter_firewall allow_input_ports { 6060 }
	go http.ListenAndServe(":6060", nil)

	dns.Debug = true

	fmt.Printf("packetlistener: Listen and send lan packets\n")
	fmt.Printf("Using interface %v \n", *nic)

	ctx, cancel := context.WithCancel(context.Background())

	s, err := packet.NewSession(*nic)
	if err != nil {
		fmt.Printf("conn error: %s", err)
		return
	}
	fmt.Printf("nicinfo: %+v\n", s.NICInfo)

	handlers := handlers{}
	handlers.netfilterIP, err = engine.SegmentLAN(*nic, s.NICInfo.HomeLAN4, s.NICInfo.HostAddr4.IP, s.NICInfo.RouterAddr4.IP)
	if err != nil {
		fmt.Println("failed to segment lan ", err)
		return
	}
	fmt.Printf("netfilter: %+v\n", handlers.netfilterIP)

	// change host IP
	if !handlers.netfilterIP.IP.Equal(s.NICInfo.HostAddr4.IP) {
		fmt.Printf("Changing host IP to %s - disable with -nodhcpip \n", handlers.netfilterIP)

		if err := packet.LinuxConfigureInterface(*nic,
			&net.IPNet{IP: s.NICInfo.HostAddr4.IP, Mask: s.NICInfo.HomeLAN4.Mask},
			&net.IPNet{IP: handlers.netfilterIP.IP, Mask: s.NICInfo.HomeLAN4.Mask}, nil); err != nil {
			fmt.Println("failed to change host IP ", err)
		}
	}

	// setup packet listener
	handlers.engine, err = engine.NewEngine(s)
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

	// ARP
	handlers.arp, err = arp.New(handlers.engine.Session())
	if err != nil {
		fmt.Printf("Failed to create arp handler nic=%s handler: %s", *nic, err)
		os.Exit(-1)
	}
	handlers.engine.AttachARP(handlers.arp)

	// ICMPv4
	handlers.icmp4, err = icmp.New4(handlers.engine.Session())
	if err != nil {
		fmt.Printf("Failed to create icmp nic=%s handler: %s", *nic, err)
		os.Exit(-1)
	}
	handlers.engine.AttachICMP4(handlers.icmp4)

	// ICMPv6
	handlers.icmp6, err = icmp.New6(handlers.engine.Session())
	if err != nil {
		fmt.Printf("Failed to create icmp6 nic=%s handler: %s", *nic, err)
		os.Exit(-1)
	}
	handlers.engine.AttachICMP6(handlers.icmp6)

	// DHCP4
	handlers.dhcp4, err = dhcp4.Config{NetfilterIP: handlers.netfilterIP, DNSServer: packet.CloudFlareDNS1, LeaseFilename: "./dhcpconfig.yaml"}.New(s)
	if err != nil {
		fmt.Printf("Failed to create dhcp4 handler: netfilterIP=%s error=%s", handlers.netfilterIP, err)
		os.Exit(-1)
	}
	handlers.engine.AttachDHCP4(handlers.dhcp4)

	go func() {
		for {
			select {
			case notification, ok := <-handlers.engine.Session().C:
				if !ok {
					return
				}
				fmt.Println("Engine notification received", notification)
			case notification, ok := <-handlers.engine.GetDNSNotificationChannel():
				if !ok {
					return
				}
				fmt.Println("DNS notification received", notification)
			case <-ctx.Done():
				return
			}
		}

	}()

	// Start server listener
	go func() {
		if err := handlers.engine.ListenAndServe(ctx); err != nil {
			if ctx.Err() != context.Canceled {
				panic(err)
			}
		}
	}()

	// handlers.radvs, _ = handlers.icmp6.StartRADVS(false, false, icmp6.MyHomePrefix, icmp6.RDNSSCLoudflare)
	// defer handlers.radvs.Stop()

	time.Sleep(time.Millisecond * 100) // time for all goroutine to start
	handlers.engine.MDNSQueryAll()
	handlers.engine.SSDPSearchAll()

	cmd(&handlers)

	handlers.engine.Close()

	cancel()
}

func doEngine(h *handlers, tokens []string) {
	var err error
	switch getString(tokens, 1) {
	case "stats":
		for _, e := range h.engine.Session().Statistics {
			fmt.Printf("%12s called %v times\n", e.Proto, e.Count)
		}

	case "attach":
		switch getString(tokens, 2) {
		case "arp":
			if h.arp != nil {
				fmt.Println("error arp is already attached")
				return
			}
			h.arp, err = arp.New(h.engine.Session())
		case "icmp4":
			if h.icmp4 != nil {
				fmt.Println("error icmp4 is already attached")
				return
			}
			h.icmp4, err = icmp.New4(h.engine.Session())
		case "icmp6":
			if h.icmp6 != nil {
				fmt.Println("error icmp6 is already attached")
				return
			}
			h.icmp6, err = icmp.New6(h.engine.Session())
		case "dhcp4":
			if h.dhcp4 != nil {
				fmt.Println("error icmp6 is already attached")
				return
			}
			h.dhcp4, err = dhcp4.Config{NetfilterIP: h.netfilterIP, DNSServer: packet.CloudFlareDNS1, LeaseFilename: "./dhcpconfig.yaml"}.New(h.engine.Session())
			// h.dhcp4, err = dhcp4.New(h.engine.Session(), h.netfilterIP, icmp.DNS6Cloudflare1, "")
		default:
			fmt.Println("invalid engine name")
			return
		}
		if err != nil {
			fmt.Println("error ", err)
			return
		}
	case "detach":
		switch getString(tokens, 2) {
		case "arp":
			err = h.engine.DetachARP()
			h.arp = nil
		case "icmp4":
			err = h.engine.DetachICMP4()
			h.icmp4 = nil
		case "icmp6":
			err = h.engine.DetachICMP6()
			h.icmp6 = nil
		case "dhcp4":
			err = h.engine.DetachDHCP4()
			h.dhcp4 = nil
		default:
			fmt.Println("invalid engine name")
		}
		if err != nil {
			fmt.Println("error ", err)
		}
	case "capture":
		if mac := getMAC(tokens, 2); mac != nil {
			if err := h.engine.Capture(mac); err != nil {
				fmt.Println("error in start hunt ", err)
			}
		}
	case "release":
		if mac := getMAC(tokens, 2); mac != nil {
			if err := h.engine.Release(mac); err != nil {
				fmt.Println("error in start hunt ", err)
			}
		}
	default:
		printHelp("invalid engine syntax", engineSyntax)
	}
}

func doARP(h *handlers, tokens []string) {
	switch getString(tokens, 1) {
	case "hunt":
		if h.arp == nil {
			fmt.Println("error arp is detached")
			return
		}
		if ip := getIP4(tokens, 2); ip != nil {
			if _, err := h.arp.StartHunt(packet.Addr{IP: ip}); err != nil {
				fmt.Println("error in start hunt ", err)
			}
		}
	case "release":
		if h.arp == nil {
			fmt.Println("error arp is detached")
			return
		}
		if ip := getIP4(tokens, 2); ip != nil {
			if _, err := h.arp.StopHunt(packet.Addr{IP: ip}); err != nil {
				fmt.Println("error in start hunt ", err)
			}
		}
	case "scan":
		if h.arp == nil {
			fmt.Println("error arp is detached")
			return
		}
		if err := h.engine.Session().ARPScan(); err != nil {
			fmt.Println("failed scan: ", err)
		}
	default:
		printHelp("invalid arp syntax", arpSyntax)
	}
}

func doICMP6(h *handlers, tokens []string) {
	if h.icmp6 == nil {
		fmt.Println("error h6 is detached")
		return
	}
	var ip net.IP
	switch getString(tokens, 1) {
	case "ns":
		if ip = getIP6(tokens, 2); ip == nil {
			return
		}
		fmt.Println("not implemented")
		/*
			if err := h.icmp6.SendNeighbourSolicitation(); err != nil {
				fmt.Printf("error in neigbour solicitation: %s\n", err)
			}
		*/
	case "ra":
		if err := h.radvs.SendRA(); err != nil {
			fmt.Printf("error in router adversitement: %s\n", err)
		}
	case "hunt":
		if ip := getIP6(tokens, 2); ip != nil {
			if _, err := h.icmp6.StartHunt(packet.Addr{IP: ip}); err != nil {
				fmt.Println("error in start hunt ", err)
			}
		}
	case "release":
		if ip := getIP6(tokens, 2); ip != nil {
			if _, err := h.icmp6.StopHunt(packet.Addr{IP: ip}); err != nil {
				fmt.Println("error in start hunt ", err)
			}
		}
	default:
		printHelp("invalid icmp6 syntax", icmp6Syntax)
	}
}

func doDHCP4(h *handlers, tokens []string) {
	switch getString(tokens, 1) {
	case "mode":
		switch getString(tokens, 2) {
		case "primary":
			h.dhcp4.SetMode(dhcp4.ModePrimaryServer)
		case "secondary":
			h.dhcp4.SetMode(dhcp4.ModeSecondaryServer)
		case "nice":
			h.dhcp4.SetMode(dhcp4.ModeSecondaryServerNice)
		default:
			fmt.Println("invalid mode syntax: dhcp4 mode [primary|secondary|nice]")
			return
		}
	default:
		printHelp("invalid dhcp4 syntax", dhcp4Syntax)
	}
}

func doMDNS(h *handlers, tokens []string) {
	switch getString(tokens, 1) {
	case "query":
		if err := h.engine.DNSHandler.SendMDNSQuery(getString(tokens, 2)); err != nil {
			fmt.Println("error:", err)
		}
	case "queryall":
		if err := h.engine.DNSHandler.SendMDNSQuery(dns.MDNSServiceDiscovery); err != nil {
			fmt.Println("error:", err)
		}
	case "sleepproxy", "sp":
		mdnsIPv4Addr := packet.Addr{MAC: packet.EthBroadcast, IP: net.IPv4(224, 0, 0, 251), Port: 5353}
		// mdnsIPv6Addr = packet.Addr{MAC: packet.EthBroadcast, IP: net.ParseIP("ff02::fb"), Port: 5353}
		if err := h.engine.DNSHandler.SendSleepProxyResponse(h.engine.Session().NICInfo.HostAddr4, mdnsIPv4Addr, 0x00, ""); err != nil {
			fmt.Println("error:", err)
		}
	case "print":
		h.engine.PrintTable()

	default:
		printHelp("invalid mdns syntax", mdnsSyntax)
	}
}

func doNBNS(h *handlers, tokens []string) {
	switch getString(tokens, 1) {
	case "query":
		if err := h.engine.DNSHandler.SendNBNSQuery(h.engine.Session().NICInfo.HostAddr4, packet.IP4BroadcastAddr, getString(tokens, 2)); err != nil {
			fmt.Println("error:", err)
		}
	case "nodestatus":
		if err := h.engine.DNSHandler.SendNBNSNodeStatus(); err != nil {
			fmt.Println("error:", err)
		}
	case "print":
		h.engine.PrintTable()

	default:
		printHelp("invalid mdns syntax", mdnsSyntax)
	}
}

func doLLMNR(h *handlers, tokens []string) {
	switch getString(tokens, 1) {
	case "query":
		if err := h.engine.DNSHandler.SendLLMNRQuery(getString(tokens, 2)); err != nil {
			fmt.Println("error:", err)
		}
	case "search": // hack to send ssdp search with "ssdp search"
		if err := h.engine.DNSHandler.SendSSDPSearch(); err != nil {
			fmt.Println("error:", err)
		}
	default:
		printHelp("invalid llmnr syntax", mdnsSyntax)
	}
}

var cmdSyntax = []string{
	"<command>                              : valid commands arp, icmp4, icmp6, dhcp4, engine",
	"log <plugin>                           : arp, icmp4, icmp6, dhcp4, engine, ip4, ip6, udp",
	"ping <ip> ",
	"dns ",
	"[quit | list]",
}
var arpSyntax = []string{
	"arp     scan",
}
var engineSyntax = []string{
	"engine  [attach | detach] <plugin>     : valid plugin=[arp|icmp4|icmp6|ip4|ip6|udp|dhcp4]",
	"        [capture | release] <mac>",
}
var dhcp4Syntax = []string{
	"dhcp4   mode [primary|secondary|nice]  : set operation mode",
}
var icmp6Syntax = []string{
	"icmp6   ra                              : router advertisement           ",
	"        ns <ip6>                        : neighbour solicitation",
}

var mdnsSyntax = []string{
	"mdns    query <service>                 : query service name             ",
	"        queryall                        : send dns-sd request            ",
	"        sp                              : send sleep proxy response      ",
	"        print                           : print ",
	"llmnr   query <service>                 : query service name             ",
	"ssdp    search                          : send ssdp search multicast     ",
}

var nbnsSyntax = []string{
	"nbns    query <service>                 : query service name             ",
	"        nodestatus                      : send node status broadcast     ",
	"        print                           : print ",
}

func printHelp(msg string, h []string) {
	if msg != "" {
		fmt.Println(msg)
	}
	for _, v := range h {
		fmt.Println(v)
	}
}

func help() {
	all := append(cmdSyntax, engineSyntax...)
	all = append(all, dhcp4Syntax...)
	all = append(all, engineSyntax...)
	all = append(all, icmp6Syntax...)
	all = append(all, arpSyntax...)
	all = append(all, mdnsSyntax...)
	all = append(all, nbnsSyntax...)
	fmt.Println("\n----")
	for _, v := range all {
		fmt.Println(v)
	}
}

func cmd(h *handlers) {

	help()
	var ip net.IP
	for {
		fmt.Println("\n----")
		fmt.Print("Enter command: ")
		tokens := readInput()

		switch tokens[0] {
		case "q", "quit":
			return
		case "l", "list":
			fmt.Println("hosts table ---")
			h.engine.PrintTable()
			if h.dhcp4 != nil {
				fmt.Println("dhcp4 table ----")
				h.dhcp4.PrintTable()
			}

		case "log":
			p := getString(tokens, 1)
			switch p {
			case "engine":
				packet.Debug = !packet.Debug
			case "ip4":
				packet.DebugIP4 = !packet.DebugIP4
			case "ip6":
				packet.DebugIP6 = !packet.DebugIP6
			case "udp":
				packet.DebugUDP = !packet.DebugUDP
			// case "icmp4":
			// icmp4.Debug = !icmp6.Debug
			case "icmp":
				icmp.Debug = !icmp.Debug
			case "arp":
				arp.Debug = !arp.Debug
			case "dhcp4":
				dhcp4.Debug = !dhcp4.Debug
			case "dns":
				dns.Debug = !dns.Debug
			default:
				fmt.Println("invalid package - use 'g icmp4|icmp6|arp|engine|ip4|ip6|dhcp4|dns'")
			}
			fmt.Println("   ip4 debug:", packet.DebugIP4)
			// fmt.Println(" icmp4 debug:", icmp4.Debug)
			fmt.Println("   ip6 debug:", packet.DebugIP6)
			fmt.Println("  icmp debug:", icmp.Debug)
			fmt.Println("engine debug:", packet.Debug)
			fmt.Println("   arp debug:", arp.Debug)
			fmt.Println(" dhcp4 debug:", dhcp4.Debug)
			fmt.Println("   udp debug:", packet.DebugUDP)
			fmt.Println("   dns debug:", dns.Debug)
		case "ping":
			if ip = getIP(tokens, 1); ip == nil {
				continue
			}
			now := time.Now()
			if ip.To4() != nil {
				if h.icmp4 == nil {
					fmt.Println("error icmp4 is detached")
					continue
				}
				// if err := h.SendEchoRequest(packet.Addr{MAC: packet.Eth4AllNodesMulticast, IP: ip}, 2, 2); err != nil {
				if err := h.icmp4.Ping(
					packet.Addr{MAC: packet.Eth4AllNodesMulticast, IP: ip}, time.Second*2); err != nil {
					if errors.Is(err, packet.ErrTimeout) {
						fmt.Println("ping timeout ")
					} else {
						fmt.Println("ping error ", err)
					}
					continue
				}
				fmt.Printf("ping %v time=%v\n", dstIP, time.Since(now))
			}
			if packet.IsIP6(ip) {
				if h.icmp6 == nil {
					fmt.Println("error icmp6 is detached")
					continue
				}
				if err := h.icmp6.Ping(
					packet.Addr{MAC: h.engine.Session().NICInfo.HostAddr4.MAC, IP: h.engine.Session().NICInfo.HostLLA.IP},
					packet.Addr{MAC: packet.Eth6AllNodesMulticast, IP: ip}, time.Second*2); err != nil {
					// if err := h6.Ping(h6.LLA().IP, ip, time.Second*2); err != nil {
					fmt.Println("icmp6 echo error ", err)
					continue
				}
				fmt.Printf("ping %v time=%v\n", dstIP, time.Since(now))
			}
		case "engine":
			doEngine(h, tokens)
		case "icmp6":
			doICMP6(h, tokens)
		case "arp":
			doARP(h, tokens)
		case "mdns":
			doMDNS(h, tokens)
		case "nbns":
			doNBNS(h, tokens)
		case "llmnr":
			doLLMNR(h, tokens)
		case "ssdp":
			doLLMNR(h, tokens) // hack to use the same handler "ssdp search"
		case "dhcp4":
			doDHCP4(h, tokens)
		case "h", "help":
			help()
		case "dns":
			h.engine.DNSHandler.PrintDNSTable()
		default:
			// do nothing
		}
	}
}
