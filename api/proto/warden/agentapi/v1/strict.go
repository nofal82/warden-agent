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
// internal package from another module. Its errors are wirescan's,
// unchanged: errors.Is matches the wirescan error values, and every error
// means the input is refused as MALFORMED.
func StrictUnmarshal(b []byte, m proto.Message) error {
	return wirescan.Unmarshal(b, m)
}
