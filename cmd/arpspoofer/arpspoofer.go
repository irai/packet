package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/arp"
	"github.com/irai/packet/fastlog"
	"github.com/irai/packet/icmp"
)

// Simple utility to demonstrate use of ARP spoofing
var (
	nic   = flag.String("i", "eth0", "nic interface")
	debug = flag.String("d", "info", "set to info or debug to show debug messages")
)

var (
	arpSpoofer   *arp.Handler
	icmp6Spoofer *icmp.Handler6
)

func main() {
	var err error
	var exiting bool

	flag.Parse()

	fmt.Println("setting up nic: ", *nic)
	s, err := packet.NewSession(*nic)
	if err != nil {
		fmt.Printf("conn error: %s", err)
		return
	}
	defer s.Close()

	// arp.Debug = *debug
	// icmp.Debug = *debug
	packet.Logger.SetLevel(fastlog.Str2LogLevel(*debug))

	// instanciate the arp spoofer for IPv4
	arpSpoofer, err = arp.New(s)
	if err != nil {
		fmt.Println("error creating arp spoofer", err)
		return
	}
	defer arpSpoofer.Close()

	// instanciate the icmp6 spoofer for IPv6
	icmp6Spoofer, err = icmp.New6(s)
	if err != nil {
		fmt.Println("error creating arp spoofer", err)
		return
	}
	defer icmp6Spoofer.Close()

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

			// memory map packet so we can access all fields
			frame, err := s.Parse(buffer[:n])
			if err != nil {
				fmt.Println("parse error", err)
				continue
			}

			switch frame.PayloadID {
			case packet.PayloadARP: // Process arp packets
				if err := arpSpoofer.ProcessPacket(frame); err != nil {
					fmt.Println("error processing arp packet", err)
				}
			case packet.PayloadICMP6: // Process icmpv6 packets
				if err := icmp6Spoofer.ProcessPacket(frame); err != nil {
					fmt.Println("error processing icmp6 packet", err)
				}
			}
		}
	}()

	// send arp scan and icmp6 echo to quickly populate host table
	arpSpoofer.Scan()
	icmp6Spoofer.PingAll()

	// start goroutine to read command line
	inputChan := make(chan []string)
	go func() {
		for {
			inputChan <- readInput()
			fmt.Println("")
		}
	}()

	// channel to terminate cleanly when we get ctrl-C or sigterm
	c := make(chan os.Signal, 2)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)

	// process commands
	for {
		fmt.Println("\n-------\nIPv4 and IPv6 Spoofer")
		fmt.Println("  log <module> error|info|debug   : change debug level for module packet|arp|icmp")
		fmt.Println("  list                            : list hosts")
		fmt.Println("  spoof <ip>                      : spoof target ip - all IPv4 trafic will be redirect to us")
		fmt.Println("  stop <ip>                       : stop spoofing ip")
		fmt.Println("  q                               : quit")
		fmt.Print("Enter command: ")

		select {
		case sig := <-c:
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				exiting = true
				arpSpoofer.Close()
				s.Close()
				time.Sleep(time.Second)
				return
			}

		case tokens := <-inputChan:
			switch tokens[0] {
			case "q":
				c <- syscall.SIGINT // force sigint exit
			case "l", "list":
				fmt.Println("hosts table ---")
				s.PrintTable()

			case "log":
				p := getString(tokens, 1)
				level := getString(tokens, 2)
				switch p {
				case "packet":
					packet.Logger.SetLevel(fastlog.Str2LogLevel(level))
				case "arp":
					arp.Logger.SetLevel(fastlog.Str2LogLevel(level))
				case "icmp":
					icmp.Logger4.SetLevel(fastlog.Str2LogLevel(level))
					icmp.Logger6.SetLevel(fastlog.Str2LogLevel(level))
				}

			case "spoof":
				ip := getIP(tokens, 1)
				if !ip.IsValid() {
					continue
				}

				host := s.FindIP(ip)
				if host == nil {
					fmt.Printf("host %s does not exist. use `list` to view all available hosts.\n", ip)
					continue
				}
				if host.Addr.IP.Is4() {
					_, err = arpSpoofer.StartHunt(host.Addr)
				} else {
					_, err = icmp6Spoofer.StartHunt(host.Addr)
					time.Sleep(time.Millisecond * 100) // time to print messages in order
				}

			case "stop":
				ip := getIP(tokens, 1)
				if !ip.IsValid() {
					continue
				}
				if host := s.FindIP(ip); host != nil {
					if host.Addr.IP.Is4() {
						_, err = arpSpoofer.StopHunt(host.Addr)
					} else {
						_, err = icmp6Spoofer.StopHunt(host.Addr)
					}
					time.Sleep(time.Millisecond * 100) // time to print messages in order
				}

			default:
			}
			if err != nil {
				fmt.Printf("error in operation %s: %v\n", tokens[0], err)
			}
		}
	}
}
