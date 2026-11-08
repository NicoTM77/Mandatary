package docker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

func TestTTYChunkBoundsPreserveBytes(t *testing.T) {
	for _, size := range []int{0, 1, 32 * 1024, 40 * 1024, MaxLogFrameBytes, MaxLogFrameBytes + 1, int(MaxLogResponseBytes)} {
		text := bytes.Repeat([]byte{'x'}, size)
		ctx, cancel := context.WithCancel(context.Background())
		s := newSDKLogStream(ctx, io.NopCloser(bytes.NewReader(text)), cancel, true, false)
		var got []byte
		for {
			f, err := s.Next(ctx)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Errorf("valid raw size %d: %v", size, err)
				break
			}
			if len(f.Payload) > MaxLogFrameBytes {
				t.Fatal("raw chunk above frame bound")
			}
			got = append(got, f.Payload...)
		}
		_ = s.Close()
		if !bytes.Equal(got, text) {
			t.Errorf("raw size %d not preserved", size)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := newSDKLogStream(ctx, io.NopCloser(bytes.NewReader(bytes.Repeat([]byte{'x'}, int(MaxLogResponseBytes)+1))), cancel, true, false)
	defer s.Close()
	got, err := io.ReadAll(s)
	if !errors.Is(err, ErrLogLimitExceeded) || int64(len(got)) > MaxLogResponseBytes {
		t.Error("raw response cap not enforced")
	}
}
