package agentapiv1

import (
	"google.golang.org/protobuf/proto"

	"github.com/nofal82/warden-agent/internal/envelope/wirescan"
)

// StrictUnmarshal decodes b into m with the shared strict decoder
// (agent-api R12, action-envelope R13 (a)–(l)). It is the only way the
// control plane decodes agent input, unsigned executor bodies included
// (redaction R45a); it never uses proto.Unmarshal, which lets the last of
// two copies of a field win, so a scan of the decoded message could miss
// what the stored bytes hold.
//
// It is wirescan.Unmarshal, re-exported because Go forbids importing an
// internal package from another module. The error values are not
// exported: a caller treats every error as MALFORMED and never tells them
// apart. On an error m is reset, so no stale or partly decoded data is left
// in it to read, log or acknowledge (R32a).
//
// A nil error covers the wire rules and UTF-8 only; the caller still
// enforces the R11 size limit before the call and the R12 enum and "sorted"
// rules and the R13 field validation after it.
func StrictUnmarshal(b []byte, m proto.Message) error {
	if err := wirescan.Unmarshal(b, m); err != nil {
		proto.Reset(m)
		return err
	}
	return nil
}
