
BIN_DIR=~/go/bin
BINARY_NAME=arpspoofer_arm
TEST_SERVER=192.168.0.107
 
all: test deploy
 
dhcpd:
	env GOOS=linux GOARCH=arm go build -o ${BIN_DIR}/dhcpd_arm cmd/dhcpd/*.go

tcpdump:
	env GOOS=linux GOARCH=arm go build -o ${BIN_DIR}/tcpdump_arm cmd/tcpdump/*.go

hosts:
	env GOOS=linux GOARCH=arm go build -o ${BIN_DIR}/hosts_arm cmd/hosts/*.go

dnslistener:
	env GOOS=linux GOARCH=arm go build -o ${BIN_DIR}/dnslistener_arm cmd/dnslistener/*.go

arpspoofer:
	#rm -f ./cmd/arpspoofer/arpspoofer_arm
	env GOOS=linux GOARCH=arm go build -o ${BIN_DIR}/arpspoofer_arm cmd/arpspoofer/*.go

build: arpspoofer dnslistener dhcpd tcpdump hosts
 
test:
	go test -v ./...
 
deploy:	build
	scp ${BIN_DIR}/*_arm netfilter@${TEST_SERVER}:/home/netfilter/bin
	#scp ${BIN_DIR}/hosts_arm netfilter@${TEST_SERVER}:/home/netfilter/bin/hosts
	#scp ${BIN_DIR}/tcpdump_arm netfilter@${TEST_SERVER}:/home/netfilter/bin/tcpdump
	#scp ${BIN_DIR}/arpspoofer_arm netfilter@${TEST_SERVER}:/home/netfilter/bin/arpspoofer
	#scp ${BIN_DIR}/packetlistener_arm netfilter@${TEST_SERVER}:/home/netfilter/bin/packetlistener
	#scp ${BIN_DIR}/dhcpd_arm netfilter@${TEST_SERVER}:/home/netfilter/bin/dhcpd
 
clean:
	go clean
	rm -f ${BIN_DIR}/arpospoofer_arm ${BIN_DIR}/packetlistener_arm ${BIN_DIR}/dhcpd_arm ${BIN_DIR}/hosts_arm  ${BIN_DIR}/tcpdump_arm  ${BIN_DIR}/dnslistener_arm 