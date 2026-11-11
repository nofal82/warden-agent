package agent

import "errors"

// Instance ID (agent-identity R31d, §4.8). The file lives in the agent's
// runtime directory, which systemd creates on a tmpfs that is cleared at
// boot (RuntimeDirectory= with RuntimeDirectoryPreserve=yes, so a restart
// keeps it): one ID per boot, never per process start.
const (
	RuntimeDir     = "/run/warden-agent"
	InstanceIDFile = "instance-id"
)

// ErrInstanceID: the runtime directory or the instance-id file is unsafe
// or holds something other than one ID.
var ErrInstanceID = errors.New("agent: instance ID")

// LoadInstanceID returns this boot's instance ID from dir/instance-id,
// creating it from 16 crypto/rand bytes when it does not exist yet. dir
// must be an absolute clean path to a directory owned by the process's
// user with no group or other permissions. The file holds exactly 32
// lowercase hex characters, mode 0600; anything else is refused (never
// replaced, so a tampered file cannot be turned into a fresh ID that
// alternates with the old one).
func LoadInstanceID(dir string) (string, error) {
	return "", errors.New("not implemented")
}
