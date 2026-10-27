package wardenv1_test

import "testing"

const wirescanPkg = module + "/internal/envelope/wirescan"

// TestWirescanNeverReachesAgentAPI (issue #19; decision 0008): agentapiv1
// gains StrictUnmarshal, which imports wirescan. The dependency must only
// ever point that way: the executor links wirescan, so if wirescan (through
// any chain of imports) reached agentapiv1, the executor would link the
// agent API, gRPC and net/http.
func TestWirescanNeverReachesAgentAPI(t *testing.T) {
	deps := transitiveDeps(t, wirescanPkg)
	if !deps[wirescanPkg] || !deps["google.golang.org/protobuf/proto"] {
		t.Fatalf("walk of %s found too little: %d packages", wirescanPkg, len(deps))
	}
	if deps[agentapiPkg] {
		t.Errorf("%s reaches %s", wirescanPkg, agentapiPkg)
	}
	if bad := violations(deps, forbiddenForExecutor); len(bad) > 0 {
		t.Errorf("%s reaches %v", wirescanPkg, bad)
	}
	if bad := violations(deps, isNet); len(bad) > 0 {
		t.Errorf("%s reaches %v", wirescanPkg, bad)
	}
}

// TestAgentAPIReachesWirescan: after issue #19 the agent API decodes
// through the shared strict decoder, so its walk reaches wirescan. This
// also shows the walk above would see the edge if it pointed the wrong
// way.
func TestAgentAPIReachesWirescan(t *testing.T) {
	if !transitiveDeps(t, agentapiPkg)[wirescanPkg] {
		t.Errorf("%s does not import %s; StrictUnmarshal must wrap the shared decoder", agentapiPkg, wirescanPkg)
	}
}
