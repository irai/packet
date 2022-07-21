package dns

import "fmt"

func (p DNS) testDecode() (e DNSEntry, err error) {
	// question for doing name decoding.  We use a single reusable question to avoid
	// name decoding on a single object via multiple DecodeFromBytes calls
	// requiring constant allocation of small byte slices.
	var buffer []byte
	var answers []byte
	var question Question

	index := 12
	question, index, err = decodeQuestion(p, index, buffer)
	if err != nil {
		fmt.Printf("dns   : error decoding questions %s %s", err, p)
		return e, err
	}

	e = newDNSEntry()
	e.Name = string(question.Name)

	if _, _, err = e.decodeAnswers(p, index, answers); err != nil {
		fmt.Printf("dns   : error decoding answers %s %s", err, p)
		return e, err
	}

	return e, nil
}
