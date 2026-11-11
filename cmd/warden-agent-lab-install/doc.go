// Command warden-agent-lab-install is the M1 lab installer (decision 0013;
// removed in M2). Run as root with the path of one enrollment bundle
// (agent-identity §4.3), it validates the bundle strictly (a bundle
// with a manifest is refused: M1 has no manifest key), then writes the
// executor's server-ID file and result-key seed (agent-identity R3,
// executor-ipc R28), the agent's root-owned trust files (R10e, §4.7), the
// executor binding file with the binding MAC (executor-ipc R52), the
// lab-trust marker, the token files in the agent state directory (R34b)
// and the warden-agent-lab systemd unit, and finally removes the bundle.
//
// It never overwrites an existing file, never follows a symlink, never
// writes, logs or keeps the binding secret, never prints the token and
// never runs another program. It is a lab tool: no release image contains
// it.
package main
