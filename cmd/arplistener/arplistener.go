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

	info, err := raw.GetNICInfo(nic)
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
	fmt.Println("nic info : ", info)

	ctx, cancel := context.WithCancel(context.Background())

	// setup packet listener
	packet, err := packet.New(nic)
	if err != nil {
		panic(err)
	}
	defer packet.Close()

	// setup ARP handler
	arpConfig := arp.Config{
		ProbeInterval:           time.Minute * 1,
		FullNetworkScanInterval: time.Minute * 20,
		PurgeDeadline:           time.Minute * 10}
	arpHandler, err := arp.New(packet.NICInfo, packet.Conn(), packet.LANHosts, arpConfig)
	packet.HandlerARP = arpHandler

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
