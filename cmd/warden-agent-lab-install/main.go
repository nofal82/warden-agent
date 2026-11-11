package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// agentUser is the unprivileged account the agent runs as. The installer
// never creates it (that needs useradd, and this command runs no other
// program); the admin creates it first.
const agentUser = "warden-agent"

const usage = "usage: warden-agent-lab-install /absolute/path/to/warden-enroll-<uuid>.json"

func main() {
	if err := run(os.Args[1:]); err != nil {
		// Errors name files and fields, never a token or secret value.
		fmt.Fprintln(os.Stderr, "warden-agent-lab-install:", err)
		os.Exit(1)
	}
	fmt.Println("warden-agent-lab-install: installed; run systemctl daemon-reload, then systemctl enable --now warden-agent-lab")
}

func run(args []string) error {
	if len(args) != 1 {
		return errors.New(usage)
	}
	p := args[0]
	if !path.IsAbs(p) || path.Clean(p) != p || p == "/" {
		return errors.New("bundle path must be absolute and clean")
	}
	if os.Geteuid() != 0 {
		return errors.New("must run as root")
	}
	if err := harden(); err != nil {
		return err
	}
	e, err := productionEnv()
	if err != nil {
		return err
	}
	return install(e, p[1:])
}

// harden keeps the binding secret and the seed out of core dumps and away
// from ptrace by other processes of the same user (executor-ipc R29 uses
// the same two settings for the seed).
func harden() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return fmt.Errorf("disable core dumps: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("set non-dumpable: %w", err)
	}
	return nil
}

func productionEnv() (env, error) {
	u, err := user.Lookup(agentUser)
	if err != nil {
		return env{}, fmt.Errorf("look up user %s (create it first): %w", agentUser, err)
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil || uid <= 0 || gid <= 0 {
		return env{}, fmt.Errorf("user %s must have a non-zero numeric uid and gid", agentUser)
	}
	return env{
		root: "/", rootUID: 0, rootGID: 0,
		agentUID: uid, agentGID: gid,
		now: time.Now, rand: rand.Reader,
	}, nil
}
