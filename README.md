# packet
Implements layer 2, IPv4, IPv6, UDP, TCP and application level packet processing.

The motivation for this package is to enable fast, memory efficient
parsing of network packets and tracking of LAN hosts. The package 
automatically track host IPs on the LAN and notifies when the IP is online offline.

## Features

* session: fast parsing of network packets without allocation
* session: auto tracking of LAN hosts and host IP changes
* session: notification of host online and offline
* naming: host naming via various protocols dhcp, mdns, ssdp, nbns, 
* arp: module to spoof arp mac table
* dhcp: module to spoof DHCP4 traffic on LAN 
* icmp6: module to spoof Local Link Address via Neigbour Discovery
* fastlog: a custom log package to log network protocols

## Fast parsing

The package is designed to operate in low power CPUs (i.e. ARM) and with limited memory. It
uses memory mapped slices to provide direct access to protocol fields without 
copying to a new structure. This technique provides fast access to fields with zero allocation and the
compiler inlines most protocol field functions to a memory reference.

## Use Session to capture raw network packets

Session provides easy access to read raw packets from the wire. Session automatically places
the nic in promiscuous mode so we receive **all** packets hiting the network card including packets sent by us.
```
	s, err := packet.NewSession("eth0")
	if err != nil {
		fmt.Printf("conn error: %s", err)
		return
	}
	defer s.Close()

	buffer := make([]byte, packet.EthMaxSize)
	for {
		n, _, err := s.ReadFrom(buffer)
		if err != nil {
			fmt.Println("error reading packet", err)
			return
		}
        // process packet...
    }
```

## Use Parse() to map a raw packet into protocol types

Parse() provides a memory mapping of protocols to slices without copying or allocation.
Given a network packet b that contains a udp frame inside an ip4 and ethernet frame, you can 
access all protocol fields after calling Parse(). Parse returns a Frame structure with accessor for all 
interesting bits.
```
  n, _, _ := s.ReadFrom(b)          // read network packet
  frame, err := session.Parse(b[:n]) // fast parse and set references
  ether := frame.Ether()            // memory mapped slice to access ether fields; return nil if not valid ethernet
  ip := frame.IP4()                 // memory mapped slice to access ipv4 fields; return nil if it does not contain IP4
  udp := frame.UDP()                // memory mapped slice to access udp fields; return nil if it does not contain UDP
  payload := frame.Payload()        // memory mapped slice to access payload

  fmt.Println("ether", ether.Src(), ether.Dst())
  fmt.Println("ip4", ip.Src(), ip.Dst())
  fmt.Println("udp", udp.SrcPort(), udp.DstPort())
  fmt.Printf("payloadID=%s payload=[%x]\n", frame.PayloadID, payload)
```

## Payload identification

Frame contains a payload ID that identifies the last payload in the packet. In most cases, this will be the application protocol ID. For example,
if the packet is a udp DHCP4 packet, PayloadID will return PayloadDHCP4 and Payload() will return a slice to the DHCP4 packet. 

```
    frame, err := s.Parse(b[:n])
    // if err

    switch frame.PayloadID {
    case packet.PayloadARP: 
        // Process arp packets
    case packet.PayloadDHCP4: 
        // Process DHCPv4 packets
    }
```

## IPv4 and IPv6 parsing

Working with IPv4, IPv6, UDP frames is fairly straight forward. For example:
```
  frame, err := packet.Parse(b[:n])
  if err != nil { panic(err)}
  
  // if you are only interested in mac and ip (either v4 or v6), 
  // frame.Src() and frame.Dst() are convenient structures to get this data.
  fmt.Println("srcAddr", frame.Src().MAC, frame.Src().IP) // will print source mac and ip
  fmt.Println("dstAddr", frame.Dst().MAC, frame.Dst().IP) // will print source mac and ip

  // if you are interested in the IPv4 fields
  if p := frame.IP4(); p != nil {
    // access ipv4 fields
    fmt.Println("version", p.Version(), "src", p.Src(), "dst", p.Dst(),"proto", p.Protocol(), "ttl", p.TTL())
  }

  // if you are intereste in the IPv6 fields
  if p := frame.IP6(); p != nil {
    fmt.Println("version", p.Version(), "src", p.Src(), "dst", p.Dst(),"nextHeader", p.NextHeader(), "hopLimit", p.HopLimit())
  }

  // if you are interested in UDP fields
  if p := frame.UDP(); p != nil {
    fmt.Println(p)
  }
```

## Session provides notifications for Host online and offline

Session tracks when a host changes to online or offline and sends notifications via a go channel.
The first time an IP is detected or when an existing host changes IP, Session sends an online notification via the notification channel.
Similarly, if an IP is not seen on the network for 5 minutes or more, Session sends an offline  notification via the notification channel.

```
s, err := packet.NewSession(*nic)
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

for {
    n, _, err := s.ReadFrom(buffer)
    if err != nil { panic(err) }

    frame, err := s.Parse(buffer[:n])
    // work on the packet...
}
```

## IPv4 and IPv6 spoofing

The package contains an arp spoofer module and a icmpv6 spoofer module
which can be used to spoof client to send all their traffic to host. The package
setup all the necessary forwarding capabilities to automatically forward
traffic to the default gateway.

Refer to the sample spoofer application.

## DHCP4 server and spoofing

need notes
refer to example dhcp server.

## ICMP6 spoofing

need notes

## DNS naming

need notes

## Examples

[arp spoofer](/cmd/arpspoofer)  
[dhcpd](/cmd/dhcpd)  
[dnslistener](/cmd/dnslistener)  
[hosts](/cmd/hosts)  
[tcpdump](/cmd/tcpdump)  


## Credits

Thanks to the following individuals for making their outstanding source code available to all to learn and re-use.

* Richard Warburton - The idea of memory mapped slices appeared when inspecting his DHCP4 library (https://github.com/krolaw/dhcp4).
* Matt Layer - Great low level raw packet processing packages (https://github.com/mdlayher/raw, https://github.com/mdlayher/ethernet)
* Gopacket Authors - Comprehensive package to process network packets (https://github.com/google/gopacket)

Many other packages contributed ideas or "code reuse" and references to these are mentioned in the source code.




