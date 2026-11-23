// Package tlsdep is a fixture: outside the executor, pulls in crypto/tls.
package tlsdep

import "crypto/tls"

// Config is only here so the import is used.
var Config = &tls.Config{MinVersion: tls.VersionTLS13}
