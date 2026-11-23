package bad

import n "net"

// Hidden dials through an aliased import.
func Hidden() {
	_, _ = n.Dial("udp", "192.0.2.1:53")
}
