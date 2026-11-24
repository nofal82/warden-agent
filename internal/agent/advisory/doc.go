// Package advisory holds the agent's advisory decoders (agent-api R52a):
// the envelope check of action-envelope R6 (size, expiry, target host)
// and the status-body hint of agent-api R31 and R38. Nothing they conclude
// is trusted: the executor re-checks every envelope itself (action-envelope
// R7), and the hints only order replies and name recovery IDs. The agent
// never interprets the envelope counters.
package advisory
