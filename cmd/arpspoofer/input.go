package main

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
)

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

func getIP(tokens []string, pos int) netip.Addr {
	if len(tokens) < pos+1 {
		fmt.Println("missing ip", tokens)
		return netip.Addr{}
	}
	ip, err := netip.ParseAddr(tokens[pos])
	if err != nil {
		fmt.Println("invalid ip=", tokens[pos], err)
		return netip.Addr{}
	}
	return ip
}

func getMAC(tokens []string, pos int) net.HardwareAddr {
	if len(tokens) < pos+1 {
		fmt.Println("missing mac", tokens)
		return nil
	}
	mac, err := net.ParseMAC(tokens[pos])
	if err != nil {
		fmt.Println("invalid mac=", tokens[pos])
		return nil
	}

	return mac
}
