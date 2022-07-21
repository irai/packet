# dhcpd example application
 
Working dhcpd to demonstrate use of the packet library. 

The server will place the network card in promiscuos mode and respond to dhcp packets sent by clients.

## "disabling" the router dhcpd server

Your LAN likely use dhcp service from the router. A safe way to "disable" it is to configure 
the router dhcp to only offer a single IP by restricting the dhcp range.
For example, assuming your network is 192.168.0.0, then set the router dhcp first ip range to 192.168.0.10 and last ip range to 192.168.0.10. 
This will ensure the router dhcp only has a single IP to offer.

To ensure your Linux server get this IP, add an entry to the  static mac->ip table so
that the IP 192.168.0.10 is only offered to your Linux server mac address.

This will force the router dhcp to offer a single IP address to your Linux box. The router will be silent
for all other requests and you can run dhcpd as a secondary dhcp server in your Linux box unhindered. In this configuration,
your LAN will have two perfectly functional dhcp servers.

## Running dhcpd

On a Linux server, you can simply run the server with -prompt to have an interactive session.
```
sudo ./dhcpd -prompt
```

## Systemd service

If you like to run dhcpd as a systemd service, this folder includes a service file ready to run.

To configure systemd on your Linux server: 
1. build the dhcpd server with `cd ./cmd/dhcpd; go install`
2. copy service file `cp ./cmd/dhcpd/dhcpd.service /etc/systemd/system`
3. update the /etc/systemd/system/dhcpd.service to match the location of the dhcpd binary and directory
4. enable the service `sudo systemctl enable dhcpd.service` 
