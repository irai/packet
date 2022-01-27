package main

// Package dnslistener contains a simple DNS listener to
// demonstrate use of packet processing and DNS processing functionality.

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/irai/packet"
	"github.com/irai/packet/dhcp4"
	"github.com/irai/packet/dns"
	"github.com/irai/packet/fastlog"
)

var (
	nic   = flag.String("i", "eth0", "nic interface")
	debug = flag.Bool("d", false, "set to true to show debug messages")
)

var dnshandler *dns.DNSHandler

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

	packet.Debug = *debug

	dnshandler, err = dns.New(s)
	if err != nil {
		fmt.Println("error creating dns handler", err)
		return
	}

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

			frame, err := s.Parse(buffer[:n])
			if err != nil {
				fmt.Println("parse error", err)
				continue
			}

			if *debug && frame.PayloadID != packet.PayloadTCP {
				frame.Log(fastlog.NewLine("dhcpd", "got packet")).Write()
			}
			switch frame.PayloadID {
			case packet.PayloadDNS:
				if _, err := dnshandler.ProcessDNS(frame); err != nil {
					fmt.Println("error processing arp packet", err)
				}

			case packet.PayloadMDNS:
				if _, _, err := dnshandler.ProcessMDNS(frame); err != nil {
					fmt.Println("error processing arp packet", err)
				}

			}
		}
	}()

	// send arp scan
	s.ARPScan()

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
				dnshandler.Close()
				s.Close()
				time.Sleep(time.Second)
				return
			}

		case tokens := <-inputChan:
			switch tokens[0] {
			case "l", "list":
				dnshandler.PrintDNSTable()
				fmt.Println("hosts table ---")
				s.PrintTable()

			case "log":
				p := getString(tokens, 1)
				switch p {
				case "packet":
					packet.Debug = !packet.Debug
				case "dhcp4", "dhcp":
					dhcp4.Debug = !dhcp4.Debug
				case "all":
					packet.Debug = !packet.Debug
					dhcp4.Debug = packet.Debug
					*debug = packet.Debug
				}

			case "q":
				c <- syscall.SIGINT

			default:
				fmt.Println("")
				fmt.Println("change log level:   log packet|dhcp|all")
				fmt.Println("list hosts      :   l|list")
				fmt.Println("quit            :   q")
			}
			if err != nil {
				fmt.Printf("error in operation %s: %v\n", tokens[0], err)
			}
		}
	}
}

func readInput() []string {
	reader := bufio.NewReader(os.Stdin)
	text, _ := reader.ReadString('\n')
	text = strings.ToLower(text[:len(text)-1])

	// handle windows line feed
	if len(text) > 1 && text[len(text)-1] == '\r' {
		text = strings.ToLower(text[:len(text)-1])
	}

	tokens := strings.Split(text, " ")
	return tokens
}

func getString(tokens []string, pos int) string {
	if len(tokens) < pos+1 {
		fmt.Println("missing value", tokens)
		return ""
	}
	return tokens[pos]
}
