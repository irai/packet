
BINARY_NAME=arpspoofer_arm
TEST_SERVER=192.168.0.107
 
all: test deploy
 
arpspoofer:
	rm -f ./cmd/arpspoofer/arpspoofer_arm
	env GOOS=linux GOARCH=arm go build -o arpspoofer_arm cmd/arpspoofer/*.go

build: arpspoofer
 
test:
	go test -v ./...
 
deploy:	build
	scp *_arm netfilter@${TEST_SERVER}:/home/netfilter/bin
 
clean:
	go clean
	rm -f ./arpospoofer