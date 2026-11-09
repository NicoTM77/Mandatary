package docker

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/container"
)

func TestSecretProjectionAcrossSDKAndMock(t *testing.T) {
	ep := mustEndpointID(t)
	token := "f0e1d2c3b4a59687f0e1d2c3b4a59687"
	for _, split := range []bool{false, true} {
		entry, cmd := []string{"app", "--password", "synthetic-short"}, []string{"--port=80"}
		if split {
			entry, cmd = []string{"app", "--password"}, []string{"synthetic-short", "--port=80"}
		}
		raw := container.InspectResponse{ID: string(testApp1ID), Config: &container.Config{Entrypoint: entry, Cmd: cmd, Env: []string{"VALUE=/long/" + token + "/file", "PATH=/usr/bin:/bin"}}}
		projected, err := SanitizeInspectConfig(ep, raw)
		if err != nil {
			t.Fatal(err)
		}
		cfg, fixtures := DefaultMockFixtures(ep)
		fixtures = append(fixtures, MockContainerFixture{ID: testApp2ID, Entrypoint: entry, Cmd: cmd, Env: raw.Config.Env})
		m, err := NewMockBackend(MockOptions{EndpointID: ep, Identity: cfg, Containers: fixtures})
		if err != nil {
			t.Fatal(err)
		}
		if err = m.VerifySelf(context.Background()); err != nil {
			t.Fatal(err)
		}
		mock, err := m.InspectConfig(context.Background(), TargetIdentity{EndpointID: ep, ContainerID: testApp2ID})
		if err != nil {
			t.Fatal(err)
		}
		_ = m.Close()
		a, tr := reviewerAdapter(t, reviewerProof())
		tr.putContainer(fakeDaemonContainer{ID: string(testApp1ID), Entrypoint: entry, Cmd: cmd, Env: raw.Config.Env})
		if err := a.VerifySelf(context.Background()); err != nil {
			t.Fatal(err)
		}
		sdk, err := a.InspectConfig(context.Background(), TargetIdentity{EndpointID: ep, ContainerID: testApp1ID})
		if err != nil {
			t.Fatal(err)
		}
		for _, got := range []InspectConfig{projected, sdk, mock} {
			data, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), "synthetic-short") || strings.Contains(string(data), token) {
				t.Error("secret survived command/env projection")
			}
			if !strings.Contains(string(data), "PATH=/usr/bin:/bin") {
				t.Error("ordinary path list changed")
			}
		}
	}
}
