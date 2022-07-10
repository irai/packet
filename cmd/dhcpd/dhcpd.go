package main

// Package dhcpd contains a simple dhcp server to
// demonstrate use of packet processing and DHCP processing functionality.

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/irai/packet"
	"github.com/irai/packet/dhcp4"
	"github.com/irai/packet/fastlog"
)

var (
	nic   = flag.String("i", "eth0", "nic interface")
	debug = flag.String("d", "info", "set to error or info or debug to control debug messages")
)

var dhcpd *dhcp4.Handler

func main() {
	var err error

	flag.Parse()

	fmt.Println("setting up nic: ", *nic)
	s, err := packet.NewSession(*nic)
	if err != nil {
		fmt.Printf("conn error: %s", err)
		return
	}
	defer s.Close()

	// Must enable IPv4 forwarding to be able to forward IP packets sent to this host as the default gw.
	if err = s.EnableIP4Forwarding(); err != nil {
		fmt.Printf("failed to set IPv4 forwarding: %s", err)
		return
	}

	packet.Logger.SetLevel(fastlog.Str2LogLevel(*debug))

	dhcpd, err = dhcp4.New(s)
	if err != nil {
		fmt.Println("error creating dhcpd", err)
		return
	}
	defer dhcpd.Close()

	// start packet processing goroutine
	go func() {
		buffer := make([]byte, packet.EthMaxSize)
		for {
			n, _, err := s.ReadFrom(buffer)
			if err != nil {
				if err != packet.ErrHandlerClosed {
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
			case packet.PayloadDHCP4:
				if err := dhcpd.ProcessPacket(frame); err != nil {
					fmt.Println("error processing arp packet", err)
				}
			}
		}
	}()

	// start goroutine to read command line and populate inputChan
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
				return // will cause defered Close() functions to run
			}

		case tokens := <-inputChan:
			switch tokens[0] {
			case "l", "list":
				dhcpd.PrintTable()
				fmt.Println("hosts table ---")
				s.PrintTable()

			case "log":
				p := getString(tokens, 1)
				level := fastlog.Str2LogLevel(getString(tokens, 2))
				switch p {
				case "packet":
					packet.Logger.SetLevel(level)
				case "dhcp4", "dhcp":
					dhcp4.Logger.SetLevel(level)
				case "all":
					packet.Logger.SetLevel(level)
					dhcp4.Logger.SetLevel(level)
				}

			case "q":
				c <- syscall.SIGINT

			default:
				fmt.Println("")
				fmt.Println("change log level:   log [packet|dhcp|all]")
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
