# packet
Implements layer 2, IPv4, IPv6, UDP, TCP and application level packet processing.

The motivation for this package is to enable a fast, memory efficient
parsing of network packets on a LAN and tracking of LAN hosts. The package will 
automatically track hosts on the LAN when it detects new traffic. It includes a 
mechanism to notify the caller when a host is online and offline.

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

  fmt.Prinln("ether", ether.Src(), ether.Dst())
  fmt.Println("ip4", ip.Src(), ip.Dst())
  fmt.Println("udp", udp.SrcPort(), udp.DstPort())
  fmt.Printf("payloadID=%s payload=[%x]\n", frame.PayloadID, payload)
```

## IPv4 and IPv6 parsing

Working with IPv4, IPv6, UDP frames is fairly straight forward. For example:
```
  frame, err := packet.Parse(b)
  if err != nil { panic(err)}
  
  var srcIP netip.Addr
  var dstIP netip.Addr
  if frame.Is4() {
      srcIP = frame.IP4().Src()
      dstIP = frame.IP4().Dst()
  }
  if frame.Is6() {
      srcIP = frame.IP6().Src()
      dstIP = frame.IP6().Dst()
  }
  fmt.Println("srcIP=%s dstIP=%s\n", srcIP, dstIP)

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

## IPv4 and IPv6 spoofing

The package contains an arp spoofer module and a icmpv6 spoofer module.
Also included is a sample application to demonstrate usage.


Credits
Thanks to the following individuals for making their outstanding source code available to all to learn and re-use.
Richard Warburton - The idea of memory mapped slices appeared when inspecting his DHCP4 library (https://github.com/krolaw/dhcp4).
Matt Layer - Great low level raw packet processing packages (https://github.com/mdlayher/raw, https://github.com/mdlayher/ethernet)


