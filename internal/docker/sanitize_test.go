package docker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	"github.com/NicoTM77/Mandatary/internal/domain"
	"github.com/docker/go-units"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/api/types/storage"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func mustEndpointID(t *testing.T) domain.EndpointID {
	t.Helper()
	id, err := domain.ParseEndpointID("11111111-2222-4333-8444-555555555555")
	if err != nil {
		t.Fatalf("parse endpoint id: %v", err)
	}
	return id
}

func assertNoCanaryLeak(t *testing.T, rendered string, canaries map[string]string) {
	t.Helper()
	for label, canary := range canaries {
		if canary != "" && strings.Contains(rendered, canary) {
			t.Fatalf("sanitized output leaked synthetic canary for class %q", label)
		}
	}
}

func TestInspectStatusAllowlistAndUnknownFields(t *testing.T) {
	epID := mustEndpointID(t)
	containerID := "aaaaaaaa11111111aaaaaaaa11111111aaaaaaaa11111111aaaaaaaa11111111"

	canaries := map[string]string{
		"env_secret":        "CANARY_ENV_VALUE_9918273645",
		"health_log_output": "CANARY_HEALTH_PROBE_OUTPUT_SECRET",
		"health_test_cmd":   "curl -u admin:CANARY_HEALTH_CMD_PASS http://localhost",
		"graph_driver_data": "/var/lib/docker/overlay2/CANARY_GRAPH_UPPERDIR",
		"resolv_conf_path":  "/var/lib/docker/containers/CANARY_RESOLV_CONF",
		"exec_id":           "CANARY_EXEC_ID_9999",
		"arbitrary_label":   "CANARY_CUSTOM_LABEL_SECRET",
		"self_label_uuid":   "22222222-3333-4444-8555-666666666666",
		"compose_secret":    "mdt_canary_token_in_compose_label_123456",
		"state_error_msg":   "oci runtime error: secret CANARY_STATE_ERR_MSG",
	}

	port80, err := network.ParsePort("80/tcp")
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	raw := container.InspectResponse{
		ID:             containerID,
		Name:           "/webapp-prod",
		Image:          "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		ResolvConfPath: canaries["resolv_conf_path"],
		HostnamePath:   "/var/lib/docker/containers/hostname",
		HostsPath:      "/var/lib/docker/containers/hosts",
		LogPath:        "/var/lib/docker/containers/json.log",
		ExecIDs:        []string{canaries["exec_id"]},
		GraphDriver: &storage.DriverData{
			Name: "overlay2",
			Data: map[string]string{"UpperDir": canaries["graph_driver_data"]},
		},
		State: &container.State{
			Status:     container.StateRunning,
			Running:    true,
			Paused:     false,
			Restarting: false,
			ExitCode:   0,
			Pid:        4242,
			Error:      canaries["state_error_msg"],
			StartedAt:  "2026-11-08T10:00:00Z",
			FinishedAt: "0001-01-01T00:00:00Z",
			Health: &container.Health{
				Status:        container.Unhealthy,
				FailingStreak: 3,
				Log: []*container.HealthcheckResult{
					{
						ExitCode: 1,
						Output:   canaries["health_log_output"],
					},
				},
			},
		},
		Config: &container.Config{
			Image: "nginx:1.27-alpine",
			Env:   []string{"APP_SECRET=" + canaries["env_secret"]},
			Healthcheck: &container.HealthConfig{
				Test: []string{"CMD-SHELL", canaries["health_test_cmd"]},
			},
			Labels: map[string]string{
				"com.docker.compose.project":       " stack-alpha ",
				"com.docker.compose.service":       canaries["compose_secret"],
				"org.opencontainers.image.version": "1.27.0",
				"io.mandatary.self":                "true",
				"io.mandatary.self.instance-uuid":  canaries["self_label_uuid"],
				"com.example.secret-label":         canaries["arbitrary_label"],
			},
		},
		NetworkSettings: &container.NetworkSettings{
			Ports: network.PortMap{
				port80: []network.PortBinding{
					{
						HostIP:   netip.MustParseAddr("127.0.0.1"),
						HostPort: "8080",
					},
				},
			},
		},
	}

	got, err := SanitizeInspectStatus(epID, raw)
	if err != nil {
		t.Fatalf("SanitizeInspectStatus failed: %v", err)
	}

	if got.EndpointID != epID {
		t.Errorf("EndpointID = %q, want %q", got.EndpointID, epID)
	}
	if string(got.ContainerID) != containerID {
		t.Errorf("ContainerID = %q, want %q", got.ContainerID, containerID)
	}
	if got.Name != "webapp-prod" {
		t.Errorf("Name = %q, want %q", got.Name, "webapp-prod")
	}
	if got.Image != "nginx:1.27-alpine" {
		t.Errorf("Image = %q, want %q", got.Image, "nginx:1.27-alpine")
	}
	if got.State != "running" || !got.Running || got.Paused || got.Restarting {
		t.Errorf("unexpected state flags: %+v", got)
	}
	if got.HealthStatus != "unhealthy" || got.HealthFailingRuns != 3 {
		t.Errorf("unexpected health: status=%q streak=%d", got.HealthStatus, got.HealthFailingRuns)
	}
	if len(got.Ports) != 1 || got.Ports[0].ContainerPort != 80 || got.Ports[0].HostPort != 8080 || got.Ports[0].Protocol != "tcp" {
		t.Errorf("unexpected ports: %+v", got.Ports)
	}
	if got.Labels["com.docker.compose.project"] != "stack-alpha" {
		t.Errorf("expected compose project label, got %+v", got.Labels)
	}
	if got.Labels["com.docker.compose.service"] != redactedValue {
		t.Errorf("expected compose service secret value to be redacted, got %q", got.Labels["com.docker.compose.service"])
	}
	if _, exists := got.Labels["io.mandatary.self"]; exists {
		t.Errorf("io.mandatary.self label must not be exposed in safe labels")
	}
	if _, exists := got.Labels["com.example.secret-label"]; exists {
		t.Errorf("non-allowlisted label must not be exposed")
	}

	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	assertNoCanaryLeak(t, string(encoded), canaries)
	assertNoCanaryLeak(t, fmt.Sprintf("%v %+v %#v", got, got, got), canaries)

	var rawMap map[string]any
	if err := json.Unmarshal(encoded, &rawMap); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	allowedTopKeys := map[string]bool{
		"endpoint_id":           true,
		"container_id":          true,
		"name":                  true,
		"image":                 true,
		"image_digest":          true,
		"state":                 true,
		"running":               true,
		"paused":                true,
		"restarting":            true,
		"exit_code":             true,
		"health_status":         true,
		"health_failing_streak": true,
		"started_at":            true,
		"finished_at":           true,
		"ports":                 true,
		"labels":                true,
	}
	for k := range rawMap {
		if !allowedTopKeys[k] {
			t.Errorf("unexpected field %q in serialized InspectStatus", k)
		}
	}
}

func TestInspectConfigEnvCommandMountAndResourceSanitization(t *testing.T) {
	epID := mustEndpointID(t)
	containerID := "bbbbbbbb22222222bbbbbbbb22222222bbbbbbbb22222222bbbbbbbb22222222"

	canaries := map[string]string{
		"api_key":          "CANARY_API_KEY_VAL_12345",
		"db_password":      "CANARY_DB_PASS_VAL_67890",
		"jwt_secret":       "CANARY_JWT_SECRET_VAL_ABCDE",
		"access_token":     "CANARY_ACCESS_TOKEN_VAL_FGHIJ",
		"credential_file":  "CANARY_CREDENTIAL_DATA_KLMNO",
		"database_dsn":     "postgres://admin:CANARY_DSN_PASS@db.internal:5432/app",
		"private_key":      "-----BEGIN PRIVATE KEY-----\nMIIBVwIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA\n-----END PRIVATE KEY-----",
		"session_cookie":   "CANARY_SESSION_COOKIE_VALUE",
		"auth_header":      "Bearer CANARY_BEARER_TOKEN_XYZ",
		"mdt_token":        "mdt_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p",
		"high_entropy_b64": "xK9#mP2$vL5@nQ8&zR1!wT4^yU7*eW0(",
		"high_entropy_hex": "0123456789abcdeffedcba98765432100123456789abcdef",
		"malformed_env":    "MALFORMED_RAW_SECRET_WITHOUT_EQUALS",
		"cmd_inline_pass":  "CANARY_CMD_INLINE_PASSWORD_999",
		"cmd_url_secret":   "redis://default:CANARY_REDIS_PASS@cache.internal:6379/0",
		"mount_secret_src": "/run/secrets/mdt_secret_mount_token_9876543210",
		"net_driver_opt":   "CANARY_NET_DRIVER_ENCRYPTED_KEY",
	}

	pidsLimit := int64(256)
	oomKillDisable := false

	raw := container.InspectResponse{
		ID:    containerID,
		Name:  "/worker-service",
		Image: "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
		ImageManifestDescriptor: &ocispec.Descriptor{
			Digest: "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		},
		Config: &container.Config{
			Image:      "ghcr.io/example/worker:v2.1.0",
			User:       "1000:1000",
			WorkingDir: "/srv/app",
			Entrypoint: []string{"/usr/local/bin/worker", "--token=" + canaries["mdt_token"]},
			Cmd: []string{
				"--db", canaries["cmd_url_secret"],
				"--password=" + canaries["cmd_inline_pass"],
				"--mode=production",
			},
			Env: []string{
				"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
				"TZ=UTC",
				"APP_ENV=production",
				"PORT=8080",
				"STRIPE_API_KEY=" + canaries["api_key"],
				"POSTGRES_PASSWORD=" + canaries["db_password"],
				"JWT_SECRET=" + canaries["jwt_secret"],
				"GITHUB_TOKEN=" + canaries["access_token"],
				"GOOGLE_APPLICATION_CREDENTIALS=" + canaries["credential_file"],
				"DATABASE_DSN=" + canaries["database_dsn"],
				"TLS_PRIVATE_CERT=" + canaries["private_key"],
				"USER_SESSION_ID=" + canaries["session_cookie"],
				"UPSTREAM_HEADER=" + canaries["auth_header"],
				"NORMAL_LOOKING_NAME=" + canaries["mdt_token"],
				"RANDOM_BLOB_VAR=" + canaries["high_entropy_b64"],
				"WEBHOOK_CHECKSUM=" + canaries["high_entropy_hex"],
				"UNSAFE_CONN_URI=" + canaries["database_dsn"],
				canaries["malformed_env"],
			},
		},
		Mounts: []container.MountPoint{
			{
				Type:        mount.TypeBind,
				Source:      "/data/app/config",
				Destination: "/etc/app",
				RW:          false,
				Propagation: mount.PropagationRPrivate,
			},
			{
				Type:        mount.TypeBind,
				Source:      canaries["mount_secret_src"],
				Destination: "/run/secrets/token",
				RW:          false,
			},
		},
		HostConfig: &container.HostConfig{
			NetworkMode:    "bridge",
			Privileged:     true,
			CapAdd:         []string{"NET_ADMIN", "SYS_ADMIN"},
			SecurityOpt:    []string{"seccomp=unconfined"},
			ReadonlyRootfs: true,
			Resources: container.Resources{
				Memory:            536870912,
				MemoryReservation: 268435456,
				MemorySwap:        1073741824,
				NanoCPUs:          1500000000,
				CPUShares:         1024,
				CPUPeriod:         100000,
				CPUQuota:          150000,
				CpusetCpus:        "0-1",
				PidsLimit:         &pidsLimit,
				OomKillDisable:    &oomKillDisable,
				Ulimits: []*units.Ulimit{
					{Name: "nofile", Soft: 65536, Hard: 65536},
				},
			},
		},
		NetworkSettings: &container.NetworkSettings{
			SandboxID:  "sandbox-secret-id",
			SandboxKey: "/var/run/docker/netns/default",
			Networks: map[string]*network.EndpointSettings{
				"app_net": {
					NetworkID:  "net-12345",
					IPAddress:  netip.MustParseAddr("172.18.0.5"),
					Gateway:    netip.MustParseAddr("172.18.0.1"),
					MacAddress: network.HardwareAddr{0x02, 0x42, 0xac, 0x12, 0x00, 0x05},
					Aliases:    []string{"worker"},
					DNSNames:   []string{"worker.app_net"},
					DriverOpts: map[string]string{"com.example.secret": canaries["net_driver_opt"]},
				},
			},
		},
	}

	got, err := SanitizeInspectConfig(epID, raw)
	if err != nil {
		t.Fatalf("SanitizeInspectConfig failed: %v", err)
	}

	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	assertNoCanaryLeak(t, string(encoded), canaries)
	assertNoCanaryLeak(t, fmt.Sprintf("%v %+v %#v", got, got, got), canaries)

	envMap := make(map[string]string, len(got.Env))
	for _, entry := range got.Env {
		k, v, ok := strings.Cut(entry, "=")
		if ok {
			envMap[k] = v
		} else {
			envMap[entry] = ""
		}
	}

	if envMap["PATH"] != "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" {
		t.Errorf("PATH should remain intact, got %q", envMap["PATH"])
	}
	if envMap["TZ"] != "UTC" || envMap["APP_ENV"] != "production" || envMap["PORT"] != "8080" {
		t.Errorf("safe env vars should remain intact, got %+v", envMap)
	}

	redactedKeys := []string{
		"STRIPE_API_KEY",
		"POSTGRES_PASSWORD",
		"JWT_SECRET",
		"GITHUB_TOKEN",
		"GOOGLE_APPLICATION_CREDENTIALS",
		"DATABASE_DSN",
		"TLS_PRIVATE_CERT",
		"USER_SESSION_ID",
		"UPSTREAM_HEADER",
		"NORMAL_LOOKING_NAME",
		"RANDOM_BLOB_VAR",
		"WEBHOOK_CHECKSUM",
		"UNSAFE_CONN_URI",
	}
	for _, k := range redactedKeys {
		if envMap[k] != redactedValue {
			t.Errorf("expected env key %q to be redacted to %q, got %q", k, redactedValue, envMap[k])
		}
	}

	if !got.Resources.ReadonlyRootfs || got.Resources.MemoryBytes != 536870912 || got.Resources.NanoCPUs != 1500000000 {
		t.Errorf("unexpected resources: %+v", got.Resources)
	}
	if len(got.Network.Networks) != 1 || got.Network.Networks[0].IPv4Address != "172.18.0.5" {
		t.Errorf("unexpected network endpoints: %+v", got.Network.Networks)
	}
}

func TestTransportAndSDKErrorsRedacted(t *testing.T) {
	canary := "CANARY_UNIX_SOCKET_TOKEN_SECRET_777"
	rawErr := errors.New("Get \"http://unix/v1.44/containers/json?secret=" + canary + "\": dial unix /var/run/docker.sock: permission denied")

	safeErr := SanitizeError(rawErr)
	if safeErr == nil {
		t.Fatal("expected non-nil sanitized error")
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	logger.Error("backend failure", slog.Any("err", safeErr))

	rendered := safeErr.Error() + " " + fmt.Sprintf("%v %+v %#v", safeErr, safeErr, safeErr) + " " + buf.String()
	assertNoCanaryLeak(t, rendered, map[string]string{
		"socket_token": canary,
		"socket_path":  "/var/run/docker.sock",
	})
}
