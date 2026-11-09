package authz

import (
	"strings"

	"github.com/NicoTM77/Mandatary/internal/docker"
	"github.com/NicoTM77/Mandatary/internal/domain"
	"github.com/NicoTM77/Mandatary/internal/store"
)

type globTokenKind uint8

const (
	globLiteral globTokenKind = iota
	globAnyChar
	globStar
	globCharClass
)

type globCharRange struct {
	lo byte
	hi byte
}

type globToken struct {
	kind    globTokenKind
	literal byte
	negated bool
	ranges  []globCharRange
}

func (t globToken) matchesByte(b byte) bool {
	switch t.kind {
	case globLiteral:
		return b == t.literal
	case globAnyChar:
		return true
	case globCharClass:
		matched := false
		for _, r := range t.ranges {
			if b >= r.lo && b <= r.hi {
				matched = true
				break
			}
		}
		if t.negated {
			return !matched
		}
		return matched
	default:
		return false
	}
}

func parseGlobPattern(pattern string) ([]globToken, error) {
	if len(pattern) == 0 || len(pattern) > 255 {
		return nil, newForbidden(ReasonInvalidSelector)
	}
	if strings.ContainsAny(pattern, "\x00\r\n\\") {
		return nil, newForbidden(ReasonInvalidSelector)
	}

	tokens := make([]globToken, 0, len(pattern))
	for i := 0; i < len(pattern); {
		c := pattern[i]
		switch c {
		case '*':
			if len(tokens) == 0 || tokens[len(tokens)-1].kind != globStar {
				tokens = append(tokens, globToken{kind: globStar})
			}
			i++
		case '?':
			tokens = append(tokens, globToken{kind: globAnyChar})
			i++
		case ']':
			return nil, newForbidden(ReasonInvalidSelector)
		case '[':
			i++
			if i >= len(pattern) {
				return nil, newForbidden(ReasonInvalidSelector)
			}
			negated := false
			if pattern[i] == '!' || pattern[i] == '^' {
				negated = true
				i++
			}
			var ranges []globCharRange
			closed := false
			for i < len(pattern) {
				if pattern[i] == ']' && len(ranges) > 0 {
					closed = true
					i++
					break
				}
				lo := pattern[i]
				if lo == '[' {
					return nil, newForbidden(ReasonInvalidSelector)
				}
				i++
				if i+1 < len(pattern) && pattern[i] == '-' && pattern[i+1] != ']' {
					hi := pattern[i+1]
					if hi < lo {
						return nil, newForbidden(ReasonInvalidSelector)
					}
					ranges = append(ranges, globCharRange{lo: lo, hi: hi})
					i += 2
				} else {
					ranges = append(ranges, globCharRange{lo: lo, hi: lo})
				}
			}
			if !closed || len(ranges) == 0 {
				return nil, newForbidden(ReasonInvalidSelector)
			}
			tokens = append(tokens, globToken{
				kind:    globCharClass,
				negated: negated,
				ranges:  ranges,
			})
		default:
			tokens = append(tokens, globToken{
				kind:    globLiteral,
				literal: c,
			})
			i++
		}
	}
	return tokens, nil
}

// MatchGlob evaluates a validated linear-time glob pattern against value.
// Unlike path.Match, '*' and '?' match any character including '/' so image
// repository patterns and container names evaluate uniformly in O(|pattern| * |value|) time.
func MatchGlob(pattern, value string) (bool, error) {
	tokens, err := parseGlobPattern(pattern)
	if err != nil {
		return false, err
	}
	if strings.ContainsAny(value, "\x00\r\n") {
		return false, nil
	}

	tIdx, vIdx := 0, 0
	starIdx, matchIdx := -1, 0

	for vIdx < len(value) {
		if tIdx < len(tokens) && (tokens[tIdx].kind == globLiteral || tokens[tIdx].kind == globAnyChar || tokens[tIdx].kind == globCharClass) && tokens[tIdx].matchesByte(value[vIdx]) {
			tIdx++
			vIdx++
		} else if tIdx < len(tokens) && tokens[tIdx].kind == globStar {
			starIdx = tIdx
			matchIdx = vIdx
			tIdx++
		} else if starIdx != -1 {
			tIdx = starIdx + 1
			matchIdx++
			vIdx = matchIdx
		} else {
			return false, nil
		}
	}

	for tIdx < len(tokens) && tokens[tIdx].kind == globStar {
		tIdx++
	}
	return tIdx == len(tokens), nil
}

// IsValidImageDigest reports whether digest is a canonical sha256:<64 lowercase hex> string.
func IsValidImageDigest(digest string) bool {
	if !strings.HasPrefix(digest, "sha256:") || len(digest) != 71 {
		return false
	}
	hexPart := digest[7:]
	for i := 0; i < len(hexPart); i++ {
		c := hexPart[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func validateCleanField(s string) bool {
	trimmed := strings.TrimSpace(s)
	if len(trimmed) == 0 || len(s) > 255 {
		return false
	}
	return !strings.ContainsAny(s, "\x00\r\n")
}

func isValidID(id string) bool {
	trimmed := strings.TrimSpace(id)
	return len(trimmed) > 0 && len(id) <= 128 && !strings.ContainsAny(id, "\x00\r\n")
}

// MatchSelector evaluates a composite ContainerSelector against a sanitized ContainerSummary.
// All present fields on the selector are conjunctive (logical AND). Optional guardrails
// and pins are enforced only when Valid is true on the selector; absent optional fields
// never restrict broad name-only or glob-only grants (TD §3.3).
func MatchSelector(sel store.ContainerSelector, target docker.ContainerSummary) (bool, error) {
	if !isValidID(sel.ID) {
		return false, newForbidden(ReasonInvalidSelector)
	}
	if _, err := domain.ParseEndpointID(string(sel.EndpointID)); err != nil {
		return false, newForbidden(ReasonInvalidSelector)
	}
	if _, err := domain.ParseEndpointID(string(target.EndpointID)); err != nil {
		return false, newForbidden(ReasonInvalidSelector)
	}
	if _, err := docker.ParseContainerID(string(target.ContainerID)); err != nil {
		return false, newForbidden(ReasonInvalidSelector)
	}

	// Self/peer protection takes precedence over any selector match.
	if docker.HasProtectedNamespaceLabel(target.Labels) {
		return false, newForbidden(ReasonSelfProtected)
	}

	// Endpoint isolation prevents cross-endpoint collisions.
	if sel.EndpointID != target.EndpointID {
		return false, nil
	}

	if sel.NameIsGlob != 0 && sel.NameIsGlob != 1 {
		return false, newForbidden(ReasonInvalidSelector)
	}
	if !validateCleanField(sel.ContainerName) {
		return false, newForbidden(ReasonInvalidSelector)
	}

	targetName := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(target.Name), "/"))
	if targetName == "" {
		return false, nil
	}

	if sel.NameIsGlob == 0 {
		// Exact name match: wildcard metacharacters are not evaluated as globs.
		if strings.ContainsAny(sel.ContainerName, "*?[]\\") {
			return false, nil
		}
		if sel.ContainerName != targetName {
			return false, nil
		}
	} else {
		matched, err := MatchGlob(sel.ContainerName, targetName)
		if err != nil {
			return false, err
		}
		if !matched {
			return false, nil
		}
	}

	// Verify target compose label consistency if both summary field and label map entry exist.
	targetProject := target.ComposeProject
	if lblProj, ok := target.Labels["com.docker.compose.project"]; ok && lblProj != "" {
		if targetProject != "" && targetProject != lblProj {
			return false, newForbidden(ReasonInvalidSelector)
		}
		targetProject = lblProj
	}
	targetService := target.ComposeService
	if lblSvc, ok := target.Labels["com.docker.compose.service"]; ok && lblSvc != "" {
		if targetService != "" && targetService != lblSvc {
			return false, newForbidden(ReasonInvalidSelector)
		}
		targetService = lblSvc
	}

	if sel.ComposeProject.Valid {
		if !validateCleanField(sel.ComposeProject.String) {
			return false, newForbidden(ReasonInvalidSelector)
		}
		if sel.ComposeProject.String != targetProject {
			return false, nil
		}
	}

	if sel.ComposeService.Valid {
		if !validateCleanField(sel.ComposeService.String) {
			return false, newForbidden(ReasonInvalidSelector)
		}
		if sel.ComposeService.String != targetService {
			return false, nil
		}
	}

	if sel.ImagePattern.Valid {
		if !validateCleanField(sel.ImagePattern.String) {
			return false, newForbidden(ReasonInvalidSelector)
		}
		matched, err := MatchGlob(sel.ImagePattern.String, target.Image)
		if err != nil {
			return false, err
		}
		if !matched {
			return false, nil
		}
	}

	if sel.PinnedContainerID.Valid {
		pinnedID, err := docker.ParseContainerID(sel.PinnedContainerID.String)
		if err != nil {
			return false, newForbidden(ReasonInvalidSelector)
		}
		if pinnedID != target.ContainerID {
			return false, nil
		}
	}

	if sel.PinnedImageDigest.Valid {
		if !IsValidImageDigest(sel.PinnedImageDigest.String) {
			return false, newForbidden(ReasonInvalidSelector)
		}
		targetDigest := strings.TrimSpace(target.ImageDigest)
		if targetDigest == "" {
			if atIdx := strings.LastIndex(target.Image, "@"); atIdx >= 0 {
				targetDigest = target.Image[atIdx+1:]
			}
		}
		if targetDigest != sel.PinnedImageDigest.String {
			return false, nil
		}
	}

	return true, nil
}
