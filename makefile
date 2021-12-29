
BINARY_NAME=arpspoofer_arm
TEST_SERVER=192.168.0.107
 
all: test deploy
 
packetlistener:
	rm -f ./cmd/packetlistener/packetlistener_arm
	env GOOS=linux GOARCH=arm go build -o packetlistener_arm cmd/packetlistener/*.go

arpspoofer:
	rm -f ./cmd/arpspoofer/arpspoofer_arm
	env GOOS=linux GOARCH=arm go build -o arpspoofer_arm cmd/arpspoofer/*.go

build: arpspoofer packetlistener
 
test:
	go test -v ./...
 
deploy:	build
	#scp arpspoofer_arm netfilter@${TEST_SERVER}:/home/netfilter/bin/arpspoofer
	scp packetlistener_arm netfilter@${TEST_SERVER}:/home/netfilter/bin/packetlistener
 
clean:
	go clean
	rm -f ./arpospoofer_arm ./packetlistener_arm