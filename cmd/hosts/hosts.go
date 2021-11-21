package main

import (
	"flag"
	"fmt"
	"net"
	"syscall"

	"github.com/irai/packet"
)

// Simple utility to list hosts on LAN
var (
	nic = flag.String("i", "eth0", "nic interface")
)

func main() {
	var err error
	flag.Parse()

	fmt.Println("setting up nic...")
	s := packet.NewSession()
	s.NICInfo, err = packet.GetNICInfo(*nic)
	if err != nil {
		fmt.Printf("interface not found nic=%s: %s\n", *nic, err)
		return
	}
	if err = s.NewPacketConn(s.NICInfo.IFI, syscall.ETH_P_ALL, packet.SocketConfig{Filter: nil, Promiscuous: true}); err != nil {
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
		}
	}()

	buffer := make([]byte, packet.EthMaxSize)
	for {
		n, _, err := s.ReadFrom(buffer)
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				fmt.Println("tmp error", err)
				continue
			}
			fmt.Println("error reading packet", err)
			return
		}

		frame, err := s.Parse(buffer[:n])
		if err != nil {
			fmt.Println("parse error", err)
			continue
		}
		s.SetOnline(frame.Host)
	}
}
