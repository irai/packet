package dhcp4

import (
	"testing"
)

func TestAttach(t *testing.T) {
	tc := setupTestHandler()

	// tc.h.clientConn = nil // don't close membuf - segfaul otherwise
	if err := tc.h.Close(); err != nil {
		panic(err)
	}

	tc.Close()

}
