// Command warden-executor is a fixture entry point.
package main

import "example.com/fixture/internal/executor/ipc"

func main() {
	_, _, _ = ipc.Listen("/run/fixture/agent.sock", "/run/fixture/root.sock")
}
