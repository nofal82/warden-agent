// Command warden-executor is a fixture entry point.
package main

import "example.com/fixture/internal/executor/bad"

func main() {
	_ = bad.Run()
	bad.Hidden()
}
