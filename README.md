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


## Packet parsing

For example, given a network packet b that contains a udp frame inside an ip4 and ethernet frame, you can 
map and access all fields in the packet via:
```
  frame, err := packet.Parse(b)
  ether := frame.Ether()  // memory mapped []byte to access ether fields
  ip := frame.IP4() // memory mapped []byte to access ipv4 fields
  udp := frame.UDP() // memory mapped []byte to access udp fields
  payload := frame.Payload() // memory mapped []byte to access payload

  fmt.Println("ether", ether.Src(), ether.Dst())
  fmt.Println("ip4", ip.Src(), ip.Dst())
  fmt.Println("udp", udp.SrcPort(), udp.DstPort())
  fmt.Printf("payloadID=%s payload=[%x]\n", frame.PayloadID, payload)
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

## Capturing network packets on linux:
```
	s, err := packet.NewSession(*nic)
    buffer := make([]byte, packet.EthMaxSize)
    for {
        n, _, err := s.ReadFrom(buffer)
        if err != nil { panic(err) }

        frame, err := s.Parse(buffer[:n])
        // work on the packet...
    }
```

## Host online and offline notifications

The package tracks when a host becomes online and when it goes offline as a
result of inactivity.  It will send a online notification when a new host
is detected or when an existing host changes its IP. It will send a offline 
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


## Credits

Thanks to the following individuals for making their outstanding source code available to all to learn and re-use.

* Richard Warburton - The idea of memory mapped slices appeared when inspecting his DHCP4 library (https://github.com/krolaw/dhcp4).
* Matt Layer - Great low level raw packet processing packages (https://github.com/mdlayher/raw, https://github.com/mdlayher/ethernet)


