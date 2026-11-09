// Package agent is the start-up sequence shared by cmd/warden-agent and
// cmd/warden-agent-lab (M1 loop): check the contract rules, load the trust
// files, decide which control-plane CAs to trust, pick the R18a start-up
// state and enroll when the state says so.
//
// Which CAs are trusted is a TrustFunc the binary passes in. The release
// binary passes KeysetTrust: in M1 there is no executor and no keyset
// cache, so it always refuses with "trust check impossible: executor
// unavailable" and the agent makes no connection (signing-and-updates
// R38). Only cmd/warden-agent-lab passes the lab fallback of decision 0013
// (package labtrust). This package never imports labtrust, so the release
// binary cannot contain it.
//
// What it does not do yet: the mutual-TLS agent stream and log collection.
// An agent that already has an identity stops after start-up.
package agent
