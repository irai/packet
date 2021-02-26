package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"log"

	"github.com/irai/packet"
	"github.com/irai/packet/arp"
	"github.com/irai/packet/raw"
)

var (
	ifaceFlag = flag.String("i", "eth0", "network interface to listen to")
	defaultGw = flag.String("g", "", "default gateway IPv4 (-g 192.168.1.1)")
)

func main() {
	flag.Parse()

	arp.Debug = true

	nic := *ifaceFlag

	ifi, ipNet4, lla, gua, err := raw.GetNICInfo(nic)
	if err != nil {
		fmt.Printf("error opening nic=%s: %s\n", nic, err)
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
	fmt.Println("mac : ", ifi.HardwareAddr)
	fmt.Println("ip4 : ", ipNet4)
	fmt.Println("lla : ", lla)
	fmt.Println("gua : ", gua)

	HomeLAN := net.IPNet{IP: ipNet4.IP.Mask(ipNet4.Mask).To4(), Mask: ipNet4.Mask}
	HomeRouterIP := net.ParseIP(*defaultGw)
	if HomeRouterIP == nil {
		HomeRouterIP, err = getLinuxDefaultGateway()
	}
	if err != nil {
		log.Fatal("cannot get default gateway ", err)
	}
	log.Print("Router IP: ", HomeRouterIP, "Home LAN: ", HomeLAN)

	ctx, cancel := context.WithCancel(context.Background())

	// setup packet listener
	packet, err := packet.New(nic)
	if err != nil {
		panic(err)
	}
	defer packet.Close()

	// setup ARP handler
	arpConfig := arp.Config{
		HostMAC: packet.HostMAC,
		// HostIP:   HostIP,
		RouterIP: HomeRouterIP, HomeLAN: HomeLAN,
		ProbeInterval:           time.Minute * 1,
		FullNetworkScanInterval: time.Minute * 20,
		PurgeDeadline:           time.Minute * 10}
	arpHandler, err := arp.New(packet.Conn(), packet.LANHosts, arpConfig)
	packet.ARP = arpHandler

	// Start server listener
	go func() {
		if err := packet.ListenAndServe(ctx); err != nil {
			if ctx.Err() != context.Canceled {
				panic(err)
			}
		}
	}()

	time.Sleep(time.Millisecond * 10) // time for all goroutine to start

	arpChannel := make(chan arp.MACEntry, 16)

	go arpNotification(arpChannel)

	cmd(packet)

	cancel()
	time.Sleep(time.Millisecond * 100)

}

func arpNotification(arpChannel chan arp.MACEntry) {
	for {
		select {
		case MACEntry := <-arpChannel:
			log.Printf("notification got ARP MACEntry for %s", MACEntry)
		}
	}
}

/*****
ALL BROKEN - TO BE DELETED - FEB 2021
***/
func cmd(packet *packet.Handler) {
	// arpHandler := packet.ARP.(*arp.Handler)
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println("Command: (q)uit | (l)ist | (f)force <mac> | (s) stop <mac> | (g) toggle log")
		fmt.Print("Enter command: ")
		text, _ := reader.ReadString('\n')
		text = strings.ToLower(text[:len(text)-1])
		fmt.Println(text)

		if text == "" || len(text) < 1 {
			continue
		}

		/**
		switch text[0] {
		case 'q':
			return
		case 'g':
			if arp.Debug {
				arp.Debug = false
			} else {
				arp.Debug = true
			}
		case 'l':
			arpHandler.PrintTable()
		case 'f':
			entry, err := getMAC(arpHandler, text)
			if err != nil {
				log.Print(err)
				break
			}
			arpHandler.StartSpoofMAC(entry.MAC)
		case 's':
			MACEntry, err := getMAC(arpHandler, text)
			if err != nil {
				log.Print(err)
				break
			}
			arpHandler.StopSpoofMAC(MACEntry.MAC)
		}
		**/
	}
}

func getMAC(text []string, pos int) net.HardwareAddr {
	if len(text) < pos-1 {
		return nil
	}
	mac, err := net.ParseMAC(text[pos])
	if err != nil {
		return nil
	}

	return mac
}

const (
	file  = "/proc/net/route"
	line  = 1    // line containing the gateway addr. (first line: 0)
	sep   = "\t" // field separator
	field = 2    // field containing hex gateway address (first field: 0)
)

// NICDefaultGateway read the default gateway from linux route file
//
// file: /proc/net/route file:
//   Iface   Destination Gateway     Flags   RefCnt  Use Metric  Mask
//   eth0    00000000    C900A8C0    0003    0   0   100 00000000    0   00
//   eth0    0000A8C0    00000000    0001    0   0   100 00FFFFFF    0   00
//
func getLinuxDefaultGateway() (gw net.IP, err error) {

	file, err := os.Open(file)
	if err != nil {
		log.Print("NIC cannot open route file ", err)
		return net.IPv4zero, err
	}
	defer file.Close()

	ipd32 := net.IP{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {

		// jump to line containing the gateway address
		for i := 0; i < line; i++ {
			scanner.Scan()
		}

		// get field containing gateway address
		tokens := strings.Split(scanner.Text(), sep)
		gatewayHex := "0x" + tokens[field]

		// cast hex address to uint32
		d, _ := strconv.ParseInt(gatewayHex, 0, 64)
		d32 := uint32(d)

		// make net.IP address from uint32
		ipd32 = make(net.IP, 4)
		binary.LittleEndian.PutUint32(ipd32, d32)
		fmt.Printf("NIC default gateway is %T --> %[1]v\n", ipd32)

		// format net.IP to dotted ipV4 string
		//ip := net.IP(ipd32).String()
		//fmt.Printf("%T --> %[1]v\n", ip)

		// exit scanner
		break
	}
	return ipd32, nil
}
