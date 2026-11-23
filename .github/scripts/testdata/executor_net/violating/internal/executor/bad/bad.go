// Package bad is a fixture: every AC2a violation the check must catch.
package bad

import (
	"net"
	"net/http"
	"syscall"

	agentapiv1 "example.com/fixture/api/proto/warden/agentapi/v1"
	"example.com/fixture/internal/other/tlsdep"
)

// Run breaks R2 and R2a in every way the scan knows.
func Run() error {
	_ = agentapiv1.Name
	_ = tlsdep.Config
	_ = http.DefaultClient
	if _, err := net.Dial("tcp", "192.0.2.1:443"); err != nil {
		return err
	}
	if _, err := net.LookupHost("example.invalid"); err != nil {
		return err
	}
	if _, err := net.Listen("unix", "/run/fixture/a.sock"); err != nil {
		return err
	}
	if _, err := net.Listen("unix", "/run/fixture/b.sock"); err != nil {
		return err
	}
	if _, err := net.Listen("tcp", "127.0.0.1:0"); err != nil {
		return err
	}
	listen := net.Listen
	_ = listen
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return err
	}
	return syscall.Close(fd)
}
