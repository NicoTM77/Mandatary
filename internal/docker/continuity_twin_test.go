package docker

import (
	"os"
	"testing"
	"time"
)

// Twin run (P1.20 R2). The whole existing suite, including the six fault-with-cancel regressions, runs at the
// package default ContinuityTTL of 0. Setting MANDATARY_CONTINUITY_TWIN=1 replays it, with no line of it changed,
// against the cached code path: every adapter that did not ask for anything else gets ContinuityTTL = 1 s and a
// clock that is 2 s later on every reading, so the snapshot is always expired when the action under test starts
// and each assertion is re-run through the single-flight refresh. Adapters built with an explicit clock (every
// test of this feature) are left alone.
//
//	MANDATARY_CONTINUITY_TWIN=1 go test -race ./internal/docker
func init() {
	if os.Getenv("MANDATARY_CONTINUITY_TWIN") == "" {
		return
	}
	sdkOptionsTestHook = func(o *SDKOptions) {
		if o.ContinuityTTL == 0 && o.Clock == nil {
			o.ContinuityTTL = time.Second
			o.Clock = (&expiringClock{}).Now
		}
	}
}

func TestTwinModeSwitch(t *testing.T) {
	a, err := NewSDKAdapter(SDKOptions{EndpointID: mustEndpointID(t), Transport: newFakeDaemonTransport()})
	if err != nil {
		t.Fatal(err)
	}
	if twin := os.Getenv("MANDATARY_CONTINUITY_TWIN") != ""; twin != (a.safety.ttl == time.Second) {
		t.Fatalf("twin mode %v but default adapter TTL is %v", twin, a.safety.ttl)
	}
	if os.Getenv("MANDATARY_CONTINUITY_TWIN") == "" && sdkOptionsTestHook != nil {
		t.Fatal("the test hook is installed without the twin switch")
	}
}
