package controlplane

import (
	"errors"

	"google.golang.org/grpc/mem"
	"google.golang.org/protobuf/proto"
)

// rawCodec is the raw-bytes codec of R11: requests are encoded
// deterministically, responses are handed over as bytes, so the size limit
// and the strict decoder run before anything is decoded. gRPC's default
// codec would decode with plain proto.Unmarshal first. The name "proto"
// keeps the standard content type, application/grpc+proto.
type rawCodec struct{}

// rawFrame receives one response message as bytes.
type rawFrame struct{ b []byte }

func (rawCodec) Name() string { return "proto" }

func (rawCodec) Marshal(v any) (mem.BufferSlice, error) {
	// A frame the stream already encoded: a stored OutboxMessage goes out
	// with the same bytes every time (R29).
	if f, ok := v.(*rawFrame); ok {
		return mem.BufferSlice{mem.SliceBuffer(f.b)}, nil
	}
	m, ok := v.(proto.Message)
	if !ok {
		return nil, errors.New("controlplane: codec: not a protobuf message")
	}
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		return nil, err
	}
	return mem.BufferSlice{mem.SliceBuffer(b)}, nil
}

func (rawCodec) Unmarshal(data mem.BufferSlice, v any) error {
	f, ok := v.(*rawFrame)
	if !ok {
		return errors.New("controlplane: codec: not a raw frame")
	}
	f.b = data.Materialize()
	return nil
}
