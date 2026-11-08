package docker

import (
	"cmp"
	"context"
	"errors"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/NicoTM77/Mandatary/internal/domain"
	"github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
)

var secretKeySubstrings = []string{
	"KEY",
	"SECRET",
	"TOKEN",
	"PASSWORD",
	"PASS",
	"CREDENTIAL",
	"DSN",
	"PRIVATE",
	"AUTH",
	"COOKIE",
	"SESSION",
	"BEARER",
}

var allowedSafeLabelKeys = map[string]struct{}{
	"com.docker.compose.project":          {},
	"com.docker.compose.service":          {},
	"com.docker.compose.container-number": {},
	"com.docker.compose.oneoff":           {},
	"org.opencontainers.image.title":      {},
	"org.opencontainers.image.version":    {},
	"org.opencontainers.image.revision":   {},
	"org.opencontainers.image.source":     {},
	"org.opencontainers.image.vendor":     {},
}

func isSecretKeyName(key string) bool {
	upper := strings.ToUpper(strings.TrimSpace(key))
	if upper == "" {
		return true
	}
	for _, sub := range secretKeySubstrings {
		if strings.Contains(upper, sub) {
			return true
		}
	}
	return false
}

func hasURLUserInfo(val string) bool {
	idx := strings.Index(val, "://")
	if idx <= 0 {
		return false
	}
	rest := val[idx+3:]
	slashIdx := strings.IndexAny(rest, "/?#")
	authority := rest
	if slashIdx >= 0 {
		authority = rest[:slashIdx]
	}
	return strings.Contains(authority, "@")
}

func isPurePOSIXPathList(val string) bool {
	if val == "" || (!strings.HasPrefix(val, "/") && !strings.Contains(val, ":/")) {
		return false
	}
	if strings.ContainsAny(val, "=?@ \t\r\n") {
		return false
	}
	lower := strings.ToLower(val)
	for _, sub := range secretKeySubstrings {
		if strings.Contains(lower, strings.ToLower(sub)) {
			return false
		}
	}
	if strings.Contains(lower, "mdt_") {
		return false
	}
	for i := 0; i < len(val); i++ {
		c := val[i]
		isAlphaNum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		isPathPunct := c == '/' || c == ':' || c == '.' || c == '-' || c == '_'
		if !isAlphaNum && !isPathPunct {
			return false
		}
	}
	return true
}

func isHexString(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var ent float64
	for _, count := range counts {
		if count == 0 {
			continue
		}
		p := float64(count) / n
		ent -= p * math.Log2(p)
	}
	return ent
}

func isSecretOrHighEntropyValue(val string) bool {
	trimmed := strings.TrimSpace(val)
	if trimmed == "" {
		return false
	}
	lower := strings.ToLower(trimmed)
	if strings.Contains(lower, "mdt_") ||
		strings.Contains(lower, "-----begin") ||
		strings.Contains(lower, "bearer ") ||
		strings.Contains(lower, "basic ") ||
		hasURLUserInfo(trimmed) {
		return true
	}

	if isPurePOSIXPathList(trimmed) {
		return false
	}

	fields := strings.FieldsFunc(trimmed, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == ',' || r == ';'
	})
	for _, token := range fields {
		if k, v, ok := strings.Cut(token, "="); ok {
			cleanKey := strings.TrimLeft(k, "-")
			if isSecretKeyName(cleanKey) || isSecretOrHighEntropyValue(v) {
				return true
			}
		}
		if isPurePOSIXPathList(token) {
			continue
		}
		if len(token) >= 32 && isHexString(token) && shannonEntropy(token) >= 3.5 {
			return true
		}
		if len(token) >= 20 && shannonEntropy(token) >= 3.75 {
			return true
		}
	}
	return false
}

// SanitizeEnvEntry redacts environment variables matching secret patterns or high-entropy rules.
func SanitizeEnvEntry(entry string) string {
	key, val, ok := strings.Cut(entry, "=")
	if !ok {
		return redactedValue
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return redactedValue
	}
	if isSecretKeyName(key) || isSecretOrHighEntropyValue(val) {
		return key + "=" + redactedValue
	}
	return key + "=" + val
}

// SanitizeEnvSlice returns a sanitized copy of container environment variables.
func SanitizeEnvSlice(env []string) []string {
	if len(env) == 0 {
		return nil
	}
	out := make([]string, len(env))
	for i, entry := range env {
		out[i] = SanitizeEnvEntry(entry)
	}
	return out
}

// FilterSafeLabels returns only allowlisted operational labels with sanitized values.
func FilterSafeLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	var out map[string]string
	for k, v := range labels {
		if _, ok := allowedSafeLabelKeys[k]; !ok {
			continue
		}
		if out == nil {
			out = make(map[string]string)
		}
		trimmed := strings.TrimSpace(v)
		if isSecretOrHighEntropyValue(trimmed) {
			out[k] = redactedValue
		} else {
			out[k] = trimmed
		}
	}
	return out
}

// SanitizeArgument redacts inline secret flags, credentials, and high-entropy values in args/mounts.
func SanitizeArgument(arg string) string {
	trimmed := strings.TrimSpace(arg)
	if trimmed == "" {
		return arg
	}
	if strings.HasPrefix(trimmed, "-") {
		if flagName, flagVal, ok := strings.Cut(trimmed, "="); ok {
			cleanKey := strings.TrimLeft(flagName, "-")
			if isSecretKeyName(cleanKey) || isSecretOrHighEntropyValue(flagVal) {
				return flagName + "=" + redactedValue
			}
			return trimmed
		}
	}
	if isSecretOrHighEntropyValue(trimmed) {
		return redactedValue
	}
	return arg
}

func sanitizeStringSlice(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = SanitizeArgument(v)
	}
	return out
}

func normalizeContainerName(name string) string {
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(name), "/"))
}

func extractPortMappings(portMap network.PortMap) []PortMapping {
	if len(portMap) == 0 {
		return nil
	}
	var ports []PortMapping
	for p, bindings := range portMap {
		if !p.IsValid() {
			continue
		}
		proto := string(p.Proto())
		cPort := p.Num()
		if len(bindings) == 0 {
			ports = append(ports, PortMapping{
				ContainerPort: cPort,
				Protocol:      proto,
			})
			continue
		}
		for _, b := range bindings {
			var hostPort uint16
			if b.HostPort != "" {
				if parsed, err := strconv.ParseUint(b.HostPort, 10, 16); err == nil {
					hostPort = uint16(parsed)
				}
			}
			var hostIP string
			if b.HostIP.IsValid() {
				hostIP = b.HostIP.String()
			}
			ports = append(ports, PortMapping{
				ContainerPort: cPort,
				Protocol:      proto,
				HostIP:        hostIP,
				HostPort:      hostPort,
			})
		}
	}
	slices.SortFunc(ports, func(a, b PortMapping) int {
		if c := cmp.Compare(a.ContainerPort, b.ContainerPort); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Protocol, b.Protocol); c != 0 {
			return c
		}
		if c := cmp.Compare(a.HostIP, b.HostIP); c != 0 {
			return c
		}
		return cmp.Compare(a.HostPort, b.HostPort)
	})
	return ports
}

func extractImageAndDigest(raw container.InspectResponse) (string, string) {
	var image string
	if raw.Config != nil && raw.Config.Image != "" {
		image = strings.TrimSpace(raw.Config.Image)
	} else {
		image = strings.TrimSpace(raw.Image)
	}
	var digest string
	if raw.ImageManifestDescriptor != nil && raw.ImageManifestDescriptor.Digest != "" {
		digest = string(raw.ImageManifestDescriptor.Digest)
	} else if strings.HasPrefix(raw.Image, "sha256:") {
		digest = raw.Image
	}
	return image, digest
}

// SanitizeInspectStatus builds an allowlisted InspectStatus from a raw SDK InspectResponse.
func SanitizeInspectStatus(endpointID domain.EndpointID, raw container.InspectResponse) (InspectStatus, error) {
	epID, err := domain.ParseEndpointID(string(endpointID))
	if err != nil {
		return InspectStatus{}, ErrInvalidTarget
	}
	cid, err := ParseContainerID(raw.ID)
	if err != nil {
		return InspectStatus{}, ErrInvalidTarget
	}

	image, digest := extractImageAndDigest(raw)
	status := InspectStatus{
		EndpointID:   epID,
		ContainerID:  cid,
		Name:         normalizeContainerName(raw.Name),
		Image:        image,
		ImageDigest:  digest,
		HealthStatus: string(container.NoHealthcheck),
	}

	if raw.State != nil {
		status.State = string(raw.State.Status)
		status.Running = raw.State.Running
		status.Paused = raw.State.Paused
		status.Restarting = raw.State.Restarting
		status.ExitCode = raw.State.ExitCode
		status.StartedAt = raw.State.StartedAt
		status.FinishedAt = raw.State.FinishedAt
		if raw.State.Health != nil && raw.State.Health.Status != "" {
			status.HealthStatus = string(raw.State.Health.Status)
			status.HealthFailingRuns = raw.State.Health.FailingStreak
		}
	}

	if raw.Config != nil {
		status.Labels = FilterSafeLabels(raw.Config.Labels)
	}

	if raw.NetworkSettings != nil {
		status.Ports = extractPortMappings(raw.NetworkSettings.Ports)
	}

	return status, nil
}

// SanitizeInspectConfig builds an allowlisted InspectConfig from a raw SDK InspectResponse.
func SanitizeInspectConfig(endpointID domain.EndpointID, raw container.InspectResponse) (InspectConfig, error) {
	epID, err := domain.ParseEndpointID(string(endpointID))
	if err != nil {
		return InspectConfig{}, ErrInvalidTarget
	}
	cid, err := ParseContainerID(raw.ID)
	if err != nil {
		return InspectConfig{}, ErrInvalidTarget
	}

	image, digest := extractImageAndDigest(raw)
	cfg := InspectConfig{
		EndpointID:  epID,
		ContainerID: cid,
		Name:        normalizeContainerName(raw.Name),
		Image:       image,
		ImageDigest: digest,
	}

	if raw.Config != nil {
		cfg.User = strings.TrimSpace(raw.Config.User)
		cfg.WorkingDir = strings.TrimSpace(raw.Config.WorkingDir)
		cfg.Entrypoint = sanitizeStringSlice(raw.Config.Entrypoint)
		cfg.Cmd = sanitizeStringSlice(raw.Config.Cmd)
		cfg.Env = SanitizeEnvSlice(raw.Config.Env)
	}

	if len(raw.Mounts) > 0 {
		mounts := make([]MountSummary, 0, len(raw.Mounts))
		for _, m := range raw.Mounts {
			mounts = append(mounts, MountSummary{
				Type:        string(m.Type),
				Name:        strings.TrimSpace(m.Name),
				Source:      SanitizeArgument(m.Source),
				Destination: m.Destination,
				ReadWrite:   m.RW,
				Propagation: string(m.Propagation),
			})
		}
		cfg.Mounts = mounts
	}

	if raw.HostConfig != nil {
		cfg.Network.NetworkMode = string(raw.HostConfig.NetworkMode)
		res := raw.HostConfig.Resources
		var pidsCopy *int64
		if res.PidsLimit != nil {
			v := *res.PidsLimit
			pidsCopy = &v
		}
		var oomCopy *bool
		if res.OomKillDisable != nil {
			v := *res.OomKillDisable
			oomCopy = &v
		}
		var ulimits []UlimitSummary
		if len(res.Ulimits) > 0 {
			ulimits = make([]UlimitSummary, 0, len(res.Ulimits))
			for _, u := range res.Ulimits {
				if u == nil {
					continue
				}
				ulimits = append(ulimits, UlimitSummary{
					Name: u.Name,
					Soft: u.Soft,
					Hard: u.Hard,
				})
			}
		}
		cfg.Resources = ResourceLimits{
			MemoryBytes:            res.Memory,
			MemoryReservationBytes: res.MemoryReservation,
			MemorySwapBytes:        res.MemorySwap,
			NanoCPUs:               res.NanoCPUs,
			CPUShares:              res.CPUShares,
			CPUPeriod:              res.CPUPeriod,
			CPUQuota:               res.CPUQuota,
			CpusetCpus:             res.CpusetCpus,
			PidsLimit:              pidsCopy,
			OomKillDisable:         oomCopy,
			ReadonlyRootfs:         raw.HostConfig.ReadonlyRootfs,
			Ulimits:                ulimits,
		}
	}

	if raw.NetworkSettings != nil {
		cfg.Network.Ports = extractPortMappings(raw.NetworkSettings.Ports)
		if len(raw.NetworkSettings.Networks) > 0 {
			nets := make([]NetworkEndpointSummary, 0, len(raw.NetworkSettings.Networks))
			for netName, ep := range raw.NetworkSettings.Networks {
				if ep == nil {
					continue
				}
				var ipv4, ipv6, gw, gw6 string
				if ep.IPAddress.IsValid() {
					ipv4 = ep.IPAddress.String()
				}
				if ep.GlobalIPv6Address.IsValid() {
					ipv6 = ep.GlobalIPv6Address.String()
				}
				if ep.Gateway.IsValid() {
					gw = ep.Gateway.String()
				}
				if ep.IPv6Gateway.IsValid() {
					gw6 = ep.IPv6Gateway.String()
				}
				var mac string
				if len(ep.MacAddress) > 0 {
					mac = ep.MacAddress.String()
				}
				nets = append(nets, NetworkEndpointSummary{
					NetworkName: netName,
					NetworkID:   ep.NetworkID,
					IPv4Address: ipv4,
					IPv6Address: ipv6,
					Gateway:     gw,
					IPv6Gateway: gw6,
					MacAddress:  mac,
					Aliases:     slices.Clone(ep.Aliases),
					DNSNames:    slices.Clone(ep.DNSNames),
				})
			}
			slices.SortFunc(nets, func(a, b NetworkEndpointSummary) int {
				return cmp.Compare(a.NetworkName, b.NetworkName)
			})
			cfg.Network.Networks = nets
		}
	}

	return cfg, nil
}

// SanitizeContainerSummary builds a sanitized ContainerSummary from a raw SDK container.Summary.
func SanitizeContainerSummary(endpointID domain.EndpointID, raw container.Summary) (ContainerSummary, error) {
	epID, err := domain.ParseEndpointID(string(endpointID))
	if err != nil {
		return ContainerSummary{}, ErrInvalidTarget
	}
	cid, err := ParseContainerID(raw.ID)
	if err != nil {
		return ContainerSummary{}, ErrInvalidTarget
	}

	var name string
	if len(raw.Names) > 0 {
		name = normalizeContainerName(raw.Names[0])
	}

	var digest string
	if raw.ImageManifestDescriptor != nil && raw.ImageManifestDescriptor.Digest != "" {
		digest = string(raw.ImageManifestDescriptor.Digest)
	} else if strings.HasPrefix(raw.ImageID, "sha256:") {
		digest = raw.ImageID
	}

	safeLabels := FilterSafeLabels(raw.Labels)
	var composeProject, composeService string
	if safeLabels != nil {
		composeProject = safeLabels["com.docker.compose.project"]
		composeService = safeLabels["com.docker.compose.service"]
	}

	return ContainerSummary{
		EndpointID:     epID,
		ContainerID:    cid,
		Name:           name,
		State:          string(raw.State),
		Status:         strings.TrimSpace(raw.Status),
		Image:          strings.TrimSpace(raw.Image),
		ImageDigest:    digest,
		ComposeProject: composeProject,
		ComposeService: composeService,
		Labels:         safeLabels,
	}, nil
}

// SanitizeError maps any SDK, HTTP, context, or transport error to a fixed safe Error sentinel.
func SanitizeError(err error) error {
	if err == nil {
		return nil
	}
	var safeErr Error
	if errors.As(err, &safeErr) {
		return safeErr
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	if errdefs.IsNotFound(err) {
		return ErrTargetNotFound
	}
	if errdefs.IsInvalidArgument(err) {
		return ErrInvalidParameter
	}
	return ErrBackendFailed
}
