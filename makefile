
BIN_DIR=~/go/bin
TEST_SERVER=192.168.0.129
 
all: test deploy
 
dhcpd:
	env GOOS=linux GOARCH=arm go build -o ${BIN_DIR}/dhcpd_arm examples/dhcpd/*.go

tcpdump:
	env GOOS=linux GOARCH=arm go build -o ${BIN_DIR}/tcpdump_arm examples/tcpdump/*.go

hosts:
	env GOOS=linux GOARCH=arm go build -o ${BIN_DIR}/hosts_arm examples/hosts/*.go

dnslistener:
	env GOOS=linux GOARCH=arm go build -o ${BIN_DIR}/dnslistener_arm examples/dnslistener/*.go

arpspoofer:
	env GOOS=linux GOARCH=arm go build -o ${BIN_DIR}/arpspoofer_arm examples/arpspoofer/*.go

build: arpspoofer dnslistener dhcpd tcpdump hosts
 
test:
	go test -v ./...
 
deploy:	build
	scp ${BIN_DIR}/*_arm netfilter@${TEST_SERVER}:/home/netfilter/bin
 
clean:
	go clean
	rm -f ${BIN_DIR}/arpospoofer_arm ${BIN_DIR}/packetlistener_arm ${BIN_DIR}/dhcpd_arm ${BIN_DIR}/hosts_arm  ${BIN_DIR}/tcpdump_arm  ${BIN_DIR}/dnslistener_arm 