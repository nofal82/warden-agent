//go:build !race

package redact

// raceEnabled widens timing bounds: the race detector slows code 5–10x.
const raceEnabled = false
