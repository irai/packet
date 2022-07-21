package packet

import (
	"testing"
)

func Test_Decode(t *testing.T) {
	// question for doing name decoding.  We use a single reusable question to avoid
	// name decoding on a single object via multiple DecodeFromBytes calls
	// requiring constant allocation of small byte slices.
	session, _ := testSession()
	defer session.Close()

	var buffer []byte
	var answers []byte
	var question Question
	frame, err := session.Parse(testWwwYouTubeCom)
	if err != nil {
		t.Fatal("error parsing", err)
	}
	p := DNS(frame.Payload())

	index := 12
	question, index, err = DecodeQuestion(p, index, buffer)
	if err != nil {
		t.Errorf("dns   : error decoding questions %s %s", err, p)
	}

	e := NewDNSEntry()
	e.Name = string(question.Name)

	if _, _, err = e.DecodeAnswers(p, index, answers); err != nil {
		t.Errorf("dns   : error decoding answers %s %s", err, p)
	}
}

/*
34:e8:94:42:29:a9 > 02:42:15:e6:10:08, ethertype IPv4 (0x0800), length 248: (tos 0x0, ttl 63, id 0, offset 0, flags [DF], proto UDP (17), length 234)
    192.168.1.1.53 > 192.168.0.129.60567: 36646 9/0/1
	www.youtube.com. CNAME youtube-ui.l.google.com.,
	youtube-ui.l.google.com. A 142.250.76.110,
	youtube-ui.l.google.com. A 142.250.204.14,
	youtube-ui.l.google.com. A 172.217.167.78,
	youtube-ui.l.google.com. A 142.250.66.238,
	youtube-ui.l.google.com. A 142.250.67.14,
	youtube-ui.l.google.com. A 142.250.71.78,
	youtube-ui.l.google.com. A 172.217.167.110,
	youtube-ui.l.google.com. A 142.250.66.206 (206)
*/
var testWwwYouTubeCom = mustHex([]byte(
	`0242 15e6 1008 34e8 9442 29a9 0800 4500` + //  .B....4..B)...E.
		`00ea 0000 4000 3f11 b830 c0a8 0101 c0a8` + //  ....@.?..0......
		`0081 0035 ec97 00d6 2019 8f26 8180 0001` + //  ...5.......&....
		`0009 0000 0001 0377 7777 0779 6f75 7475` + //  .......www.youtu
		`6265 0363 6f6d 0000 0100 01c0 0c00 0500` + //  be.com..........
		`0100 00dd 6700 160a 796f 7574 7562 652d` + //  ....g...youtube-
		`7569 016c 0667 6f6f 676c 65c0 18c0 2d00` + //  ui.l.google...-.
		`0100 0100 0000 ac00 048e fa4c 6ec0 2d00` + //  ...........Ln.-.
		`0100 0100 0000 ac00 048e facc 0ec0 2d00` + //  ..............-.
		`0100 0100 0000 ac00 04ac d9a7 4ec0 2d00` + //  ............N.-.
		`0100 0100 0000 ac00 048e fa42 eec0 2d00` + //  ...........B..-.
		`0100 0100 0000 ac00 048e fa43 0ec0 2d00` + //  ...........C..-.
		`0100 0100 0000 ac00 048e fa47 4ec0 2d00` + //  ...........GN.-.
		`0100 0100 0000 ac00 04ac d9a7 6ec0 2d00` + //  ............n.-.
		`0100 0100 0000 ac00 048e fa42 ce00 0029` + //  ...........B...)
		`1000 0000 0000 0000                    `)) //  ........
func BenchmarkEncode(b *testing.B) {
	session, _ := testSession()
	defer session.Close()

	frame, _ := session.Parse(testWwwYouTubeCom)

	b.ReportAllocs()

	b.Run("decodeName with buffer", func(b *testing.B) {
		buffer := make([]byte, 0, 64)
		for i := 0; i < b.N; i++ {
			dnsFrame := DNS(frame.Payload())
			question, index, err := DecodeQuestion(dnsFrame, 12, buffer)
			if err != nil || question.Name == nil || index == -1 {
				b.Fatal("Message.Pack() =", err, question, index)
			}
			e := NewDNSEntry()
			if _, _, err = e.DecodeAnswers(dnsFrame, index, buffer); err != nil {
				b.Fatal("Message.Pack() decode error =", err)
			}
		}
	})
	b.Run("decodeName empty buffer", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var buffer []byte
			dnsFrame := DNS(frame.Payload())
			question, index, err := DecodeQuestion(dnsFrame, 12, buffer)
			if err != nil || question.Name == nil || index == -1 {
				b.Fatal("Message.Pack() =", err, question, index)
			}
			e := NewDNSEntry()
			if _, _, err = e.DecodeAnswers(dnsFrame, index, buffer); err != nil {
				b.Fatal("Message.Pack() decode error =", err)
			}
		}
	})
}
