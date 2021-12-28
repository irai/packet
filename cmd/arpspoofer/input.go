package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/irai/packet"
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

func getIP(tokens []string, pos int) net.IP {
	if len(tokens) < pos+1 {
		fmt.Println("missing ip", tokens)
		return nil
	}
	ip := net.ParseIP(tokens[pos])
	if ip == nil || ip.IsUnspecified() {
		fmt.Println("invalid ip=", tokens[pos])
		return nil
	}
	return ip
}

func getIP4(tokens []string, pos int) net.IP {
	if len(tokens) < pos+1 {
		fmt.Println("missing ip", tokens)
		return nil
	}
	ip := net.ParseIP(tokens[pos])
	if ip == nil || ip.IsUnspecified() || ip.To4() == nil {
		fmt.Println("invalid ip=", tokens[pos])
		return nil
	}
	return ip.To4()
}

func getIP6(tokens []string, pos int) net.IP {
	if len(tokens) < pos+1 {
		fmt.Println("missing ip", tokens)
		return nil
	}
	ip := net.ParseIP(tokens[pos])
	if ip == nil || ip.IsUnspecified() || !packet.IsIP6(ip) {
		fmt.Println("invalid ip6=", tokens[pos])
		return nil
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
