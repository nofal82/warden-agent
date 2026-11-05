package controlplane

import (
	"errors"
	"fmt"
	"sync"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	agentapiv1 "github.com/nofal82/warden-agent/api/proto/warden/agentapi/v1"
	wardenv1 "github.com/nofal82/warden-agent/api/proto/warden/v1"
)

// enrollLimits are the §4.2 and §4.3 limits of the Enroll messages, read
// from the contract options so no second copy of a value exists (R52c).
type enrollLimits struct {
	request  int // EnrollRequest max_message_bytes
	response int // EnrollResponse max_message_bytes
	certMin  int // EnrollResponse.certificate min_bytes
	certMax  int // EnrollResponse.certificate max_bytes
}

var limits = sync.OnceValues(func() (l enrollLimits, err error) {
	// A broken descriptor must become an error, never a panic: Warden
	// failing must not crash the agent.
	defer func() {
		if recover() != nil {
			l, err = enrollLimits{}, errors.New("controlplane: reading the Enroll limits panicked")
		}
	}()
	req := (&agentapiv1.EnrollRequest{}).ProtoReflect().Descriptor()
	resp := (&agentapiv1.EnrollResponse{}).ProtoReflect().Descriptor()
	cert := resp.Fields().ByName("certificate")
	if cert == nil {
		return l, errors.New("controlplane: EnrollResponse.certificate missing")
	}
	for _, v := range []struct {
		dst  *int
		opts protoreflect.ProtoMessage
		ext  protoreflect.ExtensionType
	}{
		{&l.request, req.Options(), wardenv1.E_MaxMessageBytes},
		{&l.response, resp.Options(), wardenv1.E_MaxMessageBytes},
		{&l.certMin, cert.Options(), wardenv1.E_MinBytes},
		{&l.certMax, cert.Options(), wardenv1.E_MaxBytes},
	} {
		n, err := uint32Option(v.opts, v.ext)
		if err != nil {
			return enrollLimits{}, err
		}
		*v.dst = n
	}
	if l.certMin > l.certMax || l.certMax > l.response {
		return enrollLimits{}, errors.New("controlplane: inconsistent Enroll limits")
	}
	return l, nil
})

func uint32Option(opts protoreflect.ProtoMessage, ext protoreflect.ExtensionType) (int, error) {
	name := ext.TypeDescriptor().FullName()
	if opts == nil || !proto.HasExtension(opts, ext) {
		return 0, fmt.Errorf("controlplane: option %s missing", name)
	}
	n, ok := proto.GetExtension(opts, ext).(uint32)
	if !ok || n == 0 {
		return 0, fmt.Errorf("controlplane: option %s is not a positive uint32", name)
	}
	return int(n), nil
}
