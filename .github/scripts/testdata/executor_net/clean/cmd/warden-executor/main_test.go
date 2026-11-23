package main

import (
	"net"
	"testing"
)

// Tests may dial the executor's own socket as a client; they are not scanned.
func TestClientDial(t *testing.T) {
	if c, err := net.Dial("unix", "/nonexistent/fixture.sock"); err == nil {
		_ = c.Close()
	}
}
