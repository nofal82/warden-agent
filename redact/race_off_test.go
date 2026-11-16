//go:build !race

package redact

// raceEnabled turns off wall-clock bounds (wallClockChecked): the race
// detector slows the redactor about 30x.
const raceEnabled = false
