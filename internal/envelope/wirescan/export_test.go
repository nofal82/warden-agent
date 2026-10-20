package wirescan

import "google.golang.org/protobuf/reflect/protoreflect"

// CheckForTest exposes the wire scan alone to this package's external
// tests, which compare it with Unmarshal and drive it with dynamic
// descriptors. It exists only in test builds; production code reaches the
// scan through Unmarshal.
func CheckForTest(b []byte, md protoreflect.MessageDescriptor) error {
	return check(b, md, 0)
}
