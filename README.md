# packet
Implements layer 2, IPv4, IPv6, UDP, TCP and application level packet processing.

The motivation for this package is to enable a fast, memory efficient
parsing of network packets on a LAN and tracking of LAN hosts. The package will 
automatically track host IPs on the LAN and it includes a 
mechanism for notification when a host is online and offline.

The package uses memory mapped slices that provides convenient functions to read and write
network packets.

## Features

* fast parsing of network packets without allocation
* auto tracking of LAN hosts and host IP changes
* notification of host online and offline
* host naming via various protocols dhcp, mdns, ssdp, nbns
* arp module to spoof arp mac table
* dhcp module to spoof DHCP traffic on LAN

## Raw network packet reading

Session provides easy access to read raw packets from the wire. Session automatically places
the nic in promiscuous mode so we receive **all** packets hiting your network card.
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

## Packet parsing

Given a network packet b that contains a udp frame inside an ip4 and ethernet frame, you can 
map and access all fields in the packet via Parse(). Parse returns a Frame structure with accessor for all 
interesting bits.
```
  frame, err := session.Parse(b)
  ether := frame.Ether()  // memory mapped slice to access ether fields
  ip := frame.IP4() // memory mapped slice to access ipv4 fields
  udp := frame.UDP() // memory mapped slice to access udp fields
  payload := frame.Payload() // memory mapped slice to access payload

  fmt.Println("ether", ether.Src(), ether.Dst())
  fmt.Println("ip4", ip.Src(), ip.Dst())
  fmt.Println("udp", udp.SrcPort(), udp.DstPort())
  fmt.Printf("payloadID=%s payload=[%x]\n", frame.PayloadID, payload)
```

## Payload identification

Frame will always contain a payload ID that identifies the last payload in the packet. For example,
if the packet is a udp DHCP4 packet, PayloadID will return PayloadDHCP4 and Payload() will return a slice to the DHCP4 packet. 

```
    frame, err := s.Parse(buffer[:n])
    // if err

    switch frame.PayloadID {
    case packet.PayloadARP: 
        // Process arp packets
    case packet.PayloadICMP6: 
        // Process icmpv6 packets
    }
```

## IPv4 and IPv6 parsing

Working with IPv4, IPv6, UDP frames is fairly straight forward. For example:
```
  frame, err := packet.Parse(b)
  if err != nil { panic(err)}
  
  // if you are only interested in mac and ip (either v4 or v6), 
  // frame.Src() and frame.Dst() are convenient structures to get this data.
  fmt.Println("srcAddr", frame.Src().MAC, frame.Src().IP) // will print source mac and ip
  fmt.Println("dstAddr", frame.Dst().MAC, frame.Dst().IP) // will print source mac and ip

  // if you are interested in the IPv4 fields
  if frame.Is4() {
    // access ipv4 fields
    p := frame.IP4()
	fmt.Println("version", p.Version(), "src", p.Src(), "dst", p.Dst(),"proto", p.Protocol(), "ttl", p.TTL())
  }

  // if you are intereste in the IPv6 fields
  if frame.Is6() {
    p := frame.IP6()
	fmt.Println("version", p.Version(), "src", p.Src(), "dst", p.Dst(),"nextHeader", p.NextHeader(), "hopLimit", p.HopLimit())
  }

  // if you are interested in UDP fields
  if frame.IsUDP() {
      fmt.Println(frame.UDP())
  }
```

## Host online and offline notifications

Session tracks when a host becomes online and when it goes offline as a
result of inactivity.  It sends an online notification for a new host
or when an existing host changes its IP. It sends an offline 
notification when te host has not responded for a period of 5 minutes or more.

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

## ICMP6 spoofing

need notes

## DNS naming

need notes


## Credits

Thanks to the following individuals for making their outstanding source code available to all to learn and re-use.

* Richard Warburton - The idea of memory mapped slices appeared when inspecting his DHCP4 library (https://github.com/krolaw/dhcp4).
* Matt Layer - Great low level raw packet processing packages (https://github.com/mdlayher/raw, https://github.com/mdlayher/ethernet)
* Gopacket Authors - Comprehensive package to process network packets (https://github.com/google/gopacket)

Many other packages contributed ideas or "code reuse" and references to these are mentioned in the source code.




