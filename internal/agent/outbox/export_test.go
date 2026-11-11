package outbox

// Exported for the external tests and fuzz targets only.
var (
	CheckFile      = checkFile
	ParseWatermark = parseWatermark
)

// SetOpenat replaces the openat(2) call of file reads and returns a
// function that restores it.
func SetOpenat(f func(dirfd int, path string, flags int, mode uint32) (int, error)) (restore func()) {
	old := openat
	openat = f
	return func() { openat = old }
}
