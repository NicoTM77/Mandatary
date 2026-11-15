package config

import (
	"strings"
	"testing"
)

// P1.19: the three deployment settings that turn the skeleton into a packaged service.
// Every invalid value is refused with a fixed message that never echoes the input.

func TestAdminListenAddressDefaultsToLoopbackAndValidatesStrictly(t *testing.T) {
	c, err := Load(env(nil))
	if err != nil || c.AdminListenAddr != "127.0.0.1:8080" {
		t.Fatalf("default must stay loopback-only until a deployment names an address: %q %v", c.AdminListenAddr, err)
	}
	for _, addr := range []string{":8080", "0.0.0.0:8080", "127.0.0.1:9000", "[::1]:8080", "[::]:8080", "172.20.0.5:8080"} {
		c, err := Load(env(map[string]string{"MANDATARY_ADMIN_LISTEN_ADDR": addr}))
		if err != nil || c.AdminListenAddr != addr {
			t.Fatalf("%q rejected: %v", addr, err)
		}
	}
	for _, addr := range []string{"8080", ":", ":0", ":70000", ":-1", ":http", "localhost:8080", "example.invalid:8080", "127.0.0.1", "127.0.0.1:8080/", " :8080", ":8080\n", "unix:///tmp/x", "[::1]", "1.2.3.4:80:90", ":08080x"} {
		_, err := Load(env(map[string]string{"MANDATARY_ADMIN_LISTEN_ADDR": addr}))
		if err == nil || err.Error() != "invalid MANDATARY_ADMIN_LISTEN_ADDR" {
			t.Fatalf("%q accepted or echoed: %v", addr, err)
		}
	}
}

func TestDockerSocketIsAUnixSocketOnlyAndAbsentMeansNoDockerSurface(t *testing.T) {
	c, err := Load(env(nil))
	if err != nil || c.DockerSocket != "" || c.MockDocker {
		t.Fatalf("no Docker backend may be composed unless a deployment names one: %+v %v", c, err)
	}
	c, err = Load(env(map[string]string{"MANDATARY_DOCKER_SOCKET": "unix:///var/run/docker.sock"}))
	if err != nil || c.DockerSocket != "/var/run/docker.sock" {
		t.Fatalf("unix socket rejected: %q %v", c.DockerSocket, err)
	}
	for _, v := range []string{"/var/run/docker.sock", "tcp://127.0.0.1:2375", "tcp://host:2376", "ssh://u@h", "unix://relative.sock", "unix:///", "unix:///var/run/../x.sock", "unix:///var/run/dock\ner.sock", "unix:///a//b", "unix://", "http://docker", "npipe:////./pipe/docker_engine"} {
		_, err := Load(env(map[string]string{"MANDATARY_DOCKER_SOCKET": v}))
		if err == nil || err.Error() != "invalid MANDATARY_DOCKER_SOCKET" || strings.Contains(err.Error(), v) {
			t.Fatalf("%q accepted or echoed: %v", v, err)
		}
	}
}

func TestMockDockerIsExplicitAndNeverCombinedWithARealSocket(t *testing.T) {
	c, err := Load(env(map[string]string{"MANDATARY_DEV_MOCK_DOCKER": "true"}))
	if err != nil || !c.MockDocker || c.DockerSocket != "" {
		t.Fatalf("mock switch rejected: %+v %v", c, err)
	}
	c, err = Load(env(map[string]string{"MANDATARY_DEV_MOCK_DOCKER": "false"}))
	if err != nil || c.MockDocker {
		t.Fatalf("false must disable: %+v %v", c, err)
	}
	for _, v := range []string{"1", "TRUE", "yes", "True", "on"} {
		if _, err := Load(env(map[string]string{"MANDATARY_DEV_MOCK_DOCKER": v})); err == nil || err.Error() != "invalid MANDATARY_DEV_MOCK_DOCKER" {
			t.Fatalf("%q accepted: %v", v, err)
		}
	}
	// SELF-13: a mock can never silently stand beside, or fall back to, a real daemon.
	_, err = Load(env(map[string]string{"MANDATARY_DEV_MOCK_DOCKER": "true", "MANDATARY_DOCKER_SOCKET": "unix:///var/run/docker.sock"}))
	if err == nil || err.Error() != "invalid Docker backend settings" {
		t.Fatalf("mock and real socket together accepted: %v", err)
	}
}

func TestNoPhaseFourListenerCanBeConfigured(t *testing.T) {
	// TD 10.1: the operations listener is Phase 4. Only the explicit default is accepted;
	// there is no switch that could open a second listener in this release.
	if _, err := Load(env(map[string]string{"MANDATARY_OPS_UI_ENABLED": "false"})); err != nil {
		t.Fatalf("the documented default must be accepted: %v", err)
	}
	for _, c := range []map[string]string{
		{"MANDATARY_OPS_UI_ENABLED": "true"},
		{"MANDATARY_OPS_UI_ENABLED": "1"},
		{"MANDATARY_OPS_UI_ENABLED": "synthetic-unavailable-setting-canary"},
		{"MANDATARY_OPS_LISTEN_ADDR": ":8081"},
		{"MANDATARY_OPS_LISTEN_ADDR": "synthetic-unavailable-setting-canary"},
		{"MANDATARY_OPS_UI_ENABLED": "false", "MANDATARY_OPS_LISTEN_ADDR": ":8081"},
	} {
		_, err := Load(env(c))
		if err == nil || strings.Contains(err.Error(), "canary") {
			t.Fatalf("%v accepted or echoed: %v", c, err)
		}
	}
}

func TestSelfIdentityInputsAreCarriedUnvalidatedByConfigAndNeverRendered(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const uuid = "7a1c3b52-9d44-4b0e-8f21-5c6d7e8f9a0b"
	c, err := Load(env(map[string]string{"MANDATARY_SELF_CONTAINER_ID": id, "MANDATARY_SELF_INSTANCE_UUID": uuid}))
	if err != nil || c.SelfContainerID != id || c.SelfInstanceUUID != uuid {
		t.Fatalf("identity inputs not carried: %+v %v", c, err)
	}
	for _, rendered := range []string{c.String(), c.GoString(), c.LogValue().String()} {
		if strings.Contains(rendered, id) || strings.Contains(rendered, uuid) {
			t.Fatal("configuration formatting leaked a deployment identity")
		}
	}
	for _, v := range []string{"has space", "new\nline", strings.Repeat("a", 200)} {
		if _, err := Load(env(map[string]string{"MANDATARY_SELF_CONTAINER_ID": v})); err == nil {
			t.Fatalf("%q accepted", v)
		}
	}
}
