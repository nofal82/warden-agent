// Package ipc is a fixture: the shape AC2a allows (two "unix" listeners).
package ipc

import (
	"errors"
	"net"
)

// errNoDial mentions net.Dial("tcp") only inside a string and must not match.
var errNoDial = errors.New(`never net.Dial("tcp", host) or net.LookupHost`)

// Listen binds the agent and root sockets. A comment saying net.Dial is fine.
func Listen(agentPath, rootPath string) (net.Listener, *net.UnixListener, error) {
	agent, err := net.Listen("unix", agentPath)
	if err != nil {
		return nil, nil, errNoDial
	}
	root, err := net.ListenUnix("unix", &net.UnixAddr{Name: rootPath, Net: "unix"})
	if err != nil {
		return nil, nil, errors.Join(err, agent.Close())
	}
	return agent, root, nil
}
