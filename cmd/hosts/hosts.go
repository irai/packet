package main

import (
	"flag"
	"fmt"

	"github.com/irai/packet"
)

// Simple utility to list hosts on LAN
var (
	nic = flag.String("i", "eth0", "nic interface")
)

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
		s.Notify(frame)
	}
}
