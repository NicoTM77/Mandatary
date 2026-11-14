package backup

import (
	"context"
	"database/sql"
	"encoding/base64"
	"io"
	"sort"
	"time"

	"github.com/NicoTM77/Mandatary/internal/domain"
	"github.com/NicoTM77/Mandatary/internal/store"
)

// Authorizer decides, INSIDE the transaction that is about to read or change state, whether the
// initiator may proceed. It receives the live control state and the server clock; it must derive
// everything from persisted state, never from what the caller says about itself. Returning any
// error refuses the operation before anything is written.
type Authorizer func(ctx context.Context, q *store.Queries, c store.InstallationControl, now int64) error

// Service is the logical backup and restore service over one repository.
type Service struct {
	repo    *store.Repository
	version string
	now     func() time.Time
	random  io.Reader
	// step is a test seam: a non-nil error aborts the restore at that named point exactly as a
	// failure there would. Production leaves it nil.
	step func(name string) error
}

// New binds the service to a repository. version is the build identity recorded (informationally)
// in every archive.
func New(repo *store.Repository, version string) (*Service, error) {
	if repo == nil || version == "" || len(version) > 128 {
		return nil, ErrUnavailable
	}
	return &Service{repo: repo, version: version, now: time.Now, random: newRandomReader()}, nil
}

func (s *Service) hook(name string) error {
	if s.step == nil {
		return nil
	}
	return s.step(name)
}

// ExportInfo is the non-secret result summary of an export.
type ExportInfo struct {
	BackupID string         `json:"backup_id"`
	Mode     Mode           `json:"mode"`
	Counts   map[string]int `json:"counts"`
}

func ptrNull(n sql.NullInt64) *int64 {
	if !n.Valid {
		return nil
	}
	v := n.Int64
	return &v
}

func ptrNullStr(n sql.NullString) *string {
	if !n.Valid {
		return nil
	}
	v := n.String
	return &v
}

func nullInt(p *int64) sql.NullInt64 {
	if p == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: *p, Valid: true}
}

func nullStr(p *string) sql.NullString {
	if p == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *p, Valid: true}
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

type exportRows struct {
	endpoints []store.Endpoint
	users     []store.User
	groups    []store.Group
	agents    []store.Agent
	userMem   []store.UserGroupMembership
	agentMem  []store.AgentGroupMembership
	roles     []store.AdministrativeRole
	selectors []store.ContainerSelector
	policies  []store.Policy
	addresses []store.NotificationAddress
	auths     []store.Authenticator
	creds     []store.AgentCredential
	waUsers   []store.WebauthnUser
	waRecords []store.WebauthnCredential
}

// Export reads one coherent snapshot and returns the signed archive. authorize runs first, inside
// that snapshot. Export never reads session, usage, setup, recovery, notice or control state.
func (s *Service) Export(ctx context.Context, mode Mode, authorize Authorizer) ([]byte, ExportInfo, error) {
	if mode != ModeFull && mode != ModeClean {
		return nil, ExportInfo{}, ErrInvalid
	}
	var rows exportRows
	var denied error
	err := s.repo.Read(ctx, func(q *store.Queries) error {
		c, err := q.GetInstallationControl(ctx)
		if err != nil {
			return err
		}
		if authorize == nil {
			denied = ErrDenied
			return denied
		}
		if e := authorize(ctx, q, c, s.now().Unix()); e != nil {
			denied = ErrDenied
			return denied
		}
		return s.readRows(ctx, q, mode, &rows)
	})
	if denied != nil {
		return nil, ExportInfo{}, denied
	}
	if err != nil {
		return nil, ExportInfo{}, ErrUnavailable
	}
	archive, counts, err := s.build(mode, rows)
	if err != nil {
		return nil, ExportInfo{}, err
	}
	raw, err := marshalArchive(archive)
	if err != nil {
		return nil, ExportInfo{}, err
	}
	return raw, ExportInfo{BackupID: archive.BackupID, Mode: mode, Counts: counts}, nil
}

func marshalArchive(a Archive) ([]byte, error) {
	raw, err := jsonMarshal(a)
	if err != nil || len(raw) > MaxArchiveBytes {
		return nil, ErrUnavailable
	}
	return raw, nil
}

func (s *Service) readRows(ctx context.Context, q *store.Queries, mode Mode, r *exportRows) (err error) {
	if r.endpoints, err = q.BackupListEndpoints(ctx); err != nil {
		return err
	}
	if r.users, err = q.ListUsers(ctx); err != nil {
		return err
	}
	if r.groups, err = q.ListGroups(ctx); err != nil {
		return err
	}
	if r.agents, err = q.ListAgents(ctx); err != nil {
		return err
	}
	if r.userMem, err = q.BackupListUserMemberships(ctx); err != nil {
		return err
	}
	if r.agentMem, err = q.BackupListAgentMemberships(ctx); err != nil {
		return err
	}
	if r.roles, err = q.BackupListRoles(ctx); err != nil {
		return err
	}
	if r.selectors, err = q.BackupListSelectors(ctx); err != nil {
		return err
	}
	if r.policies, err = q.ListAllPolicies(ctx); err != nil {
		return err
	}
	if r.addresses, err = q.BackupListAddresses(ctx); err != nil {
		return err
	}
	if mode != ModeFull {
		return nil
	}
	if r.auths, err = q.BackupListActiveAuthenticators(ctx); err != nil {
		return err
	}
	if r.creds, err = q.BackupListActiveMachineRecords(ctx); err != nil {
		return err
	}
	if r.waUsers, err = q.BackupListWebauthnUsers(ctx); err != nil {
		return err
	}
	r.waRecords, err = q.BackupListWebauthnRecords(ctx)
	return err
}

func (s *Service) build(mode Mode, r exportRows) (Archive, map[string]int, error) {
	var sc Scope
	for _, e := range r.endpoints {
		sc.Endpoints = append(sc.Endpoints, EndpointRecord{ID: string(e.ID), Slug: e.Slug, Name: e.Name, Transport: e.Transport, SourceState: e.State})
	}
	for _, u := range r.users {
		sc.Users = append(sc.Users, UserRecord{ID: u.ID, Username: u.Username, MFARequirement: u.MfaRequirement, Compromised: u.Compromised != 0, SourceState: u.State})
	}
	for _, g := range r.groups {
		sc.Groups = append(sc.Groups, GroupRecord{ID: g.ID, Name: g.Name, SourceState: g.State})
	}
	for _, a := range r.agents {
		sc.Agents = append(sc.Agents, AgentRecord{ID: a.ID, Name: a.Name, OwnerUserID: ptrNullStr(a.OwnerUserID), OwnerGroupID: ptrNullStr(a.OwnerGroupID), SourceState: a.State})
	}
	for _, m := range r.userMem {
		sc.UserMemberships = append(sc.UserMemberships, UserMembershipRecord{UserID: m.UserID, GroupID: m.GroupID, SourceState: m.State})
	}
	for _, m := range r.agentMem {
		sc.AgentMemberships = append(sc.AgentMemberships, AgentMembershipRecord{AgentID: m.AgentID, GroupID: m.GroupID, SourceState: m.State})
	}
	for _, x := range r.roles {
		rec := RoleRecord{ID: x.ID, UserID: x.UserID, Role: x.Role, SourceState: x.State}
		if x.EndpointID != nil {
			v := string(*x.EndpointID)
			rec.EndpointID = &v
		}
		sc.Roles = append(sc.Roles, rec)
	}
	for _, x := range r.selectors {
		sc.Selectors = append(sc.Selectors, SelectorRecord{ID: x.ID, EndpointID: string(x.EndpointID), ContainerName: x.ContainerName, NameIsGlob: x.NameIsGlob != 0,
			ComposeProject: ptrNullStr(x.ComposeProject), ComposeService: ptrNullStr(x.ComposeService), ImagePattern: ptrNullStr(x.ImagePattern),
			PinnedContainerID: ptrNullStr(x.PinnedContainerID), PinnedImageDigest: ptrNullStr(x.PinnedImageDigest)})
	}
	for _, p := range r.policies {
		sc.Policies = append(sc.Policies, PolicyRecord{ID: p.ID, UserID: ptrNullStr(p.UserID), GroupID: ptrNullStr(p.GroupID), AgentID: ptrNullStr(p.AgentID),
			EndpointID: string(p.EndpointID), SelectorID: p.SelectorID, Operation: p.Operation, Effect: p.Effect,
			LogTailMax: ptrNull(p.LogTailMax), StopTimeoutMax: ptrNull(p.StopTimeoutMax), SourceState: p.State})
	}
	for _, a := range r.addresses {
		sc.Addresses = append(sc.Addresses, AddressRecord{ID: a.ID, UserID: a.UserID, Address: a.Address, Version: a.Version, CreatedAt: a.CreatedAt})
	}
	payload := secretPayload{Authenticators: map[string]authenticatorSecret{}, AgentCredentials: map[string][]byte{}, WebauthnUsers: map[string][]byte{}, WebauthnRecords: map[string][]byte{}}
	exportedAuth := map[string]bool{}
	exportedUser := map[string]bool{}
	for _, a := range r.auths {
		sec := authenticatorSecret{CreatedAt: a.CreatedAt, BoundAt: ptrNull(a.BoundAt), ExpiresAt: ptrNull(a.ExpiresAt), VerifierHash: a.VerifierHash, PublicKey: a.PublicKey,
			ExternalCredentialID: a.ExternalCredentialID, PasswordCodepoints: ptrNull(a.PasswordCodepoints), PasswordFormat: ptrNullStr(a.PasswordFormat),
			MaxAssurance: a.MaxAssurance, PhishingResistant: ptrNull(a.PhishingResistant), RetryCeiling: a.RetryCeiling, LastAcceptedTOTPStep: ptrNull(a.LastAcceptedTotpStep),
			SignCount: ptrNull(a.SignCount), BackupEligible: ptrNull(a.BackupEligible), BackupState: ptrNull(a.BackupState), UserVerified: ptrNull(a.UserVerified),
			TOTPAlgorithm: ptrNullStr(a.TotpAlgorithm)}
		if a.Kind == "totp" {
			seed, err := s.repo.DecryptSecret("totp", a.ID, a.EncryptedSecret)
			if err != nil {
				return Archive{}, nil, ErrUnavailable
			}
			sec.TOTPSeed = seed
		}
		payload.Authenticators[a.ID] = sec
		exportedAuth[a.ID] = true
		exportedUser[a.UserID] = true
		sc.Authenticators = append(sc.Authenticators, AuthenticatorRecord{ID: a.ID, UserID: a.UserID, Kind: a.Kind, SourceState: a.State})
	}
	for _, c := range r.creds {
		payload.AgentCredentials[c.ID] = c.TokenHash
		sc.AgentCredentials = append(sc.AgentCredentials, AgentCredentialRecord{ID: c.ID, AgentID: c.AgentID, DisplayPrefix: c.DisplayPrefix, IssuedAt: c.IssuedAt,
			ExpiresAt: ptrNull(c.ExpiresAt), NonexpiringApproved: c.NonexpiringApproved != 0, SourceState: c.State})
	}
	for _, w := range r.waUsers {
		if exportedUser[w.UserID] {
			payload.WebauthnUsers[w.UserID] = w.Handle
		}
	}
	for _, w := range r.waRecords {
		if !exportedAuth[w.AuthenticatorID] {
			continue
		}
		plain, err := s.repo.DecryptSecret("webauthn-credential", w.AuthenticatorID, w.Envelope)
		if err != nil {
			return Archive{}, nil, ErrUnavailable
		}
		payload.WebauthnRecords[w.AuthenticatorID] = plain
	}
	id, err := domain.NewUUID(s.random)
	if err != nil {
		return Archive{}, nil, ErrUnavailable
	}
	hmacSalt, err := randomBytes(s.random, saltBytes)
	if err != nil {
		return Archive{}, nil, err
	}
	a := Archive{Format: Format, SchemaVersion: ArchiveVersion, DatabaseSchemaVersion: store.SchemaVersion(), MandataryVersion: s.version,
		CreatedAt: s.now().UTC().Format(time.RFC3339), BackupID: id, Mode: mode, HMACSalt: base64.StdEncoding.EncodeToString(hmacSalt), Scope: normalizeScope(sc)}
	if mode == ModeFull {
		sealSalt, err := randomBytes(s.random, saltBytes)
		if err != nil {
			return Archive{}, nil, err
		}
		nonce, err := randomBytes(s.random, 12)
		if err != nil {
			return Archive{}, nil, err
		}
		key, err := s.repo.DeriveBackupKey(secretsInfo, sealSalt)
		if err != nil {
			return Archive{}, nil, ErrUnavailable
		}
		defer clear(key)
		ct, err := sealPayload(a, key, nonce, payload)
		if err != nil {
			return Archive{}, nil, err
		}
		a.Secrets = &Sealed{Salt: base64.StdEncoding.EncodeToString(sealSalt), Nonce: base64.StdEncoding.EncodeToString(nonce), Ciphertext: base64.StdEncoding.EncodeToString(ct)}
	}
	canonical, err := a.canonical()
	if err != nil {
		return Archive{}, nil, ErrUnavailable
	}
	macKey, err := s.repo.DeriveBackupKey(integrityInfo, hmacSalt)
	if err != nil {
		return Archive{}, nil, ErrUnavailable
	}
	defer clear(macKey)
	a.ContentDigest = digestOf(canonical)
	a.IntegrityHMAC = tagOf(macKey, canonical)
	if err := validateScope(a.Scope, mode); err != nil {
		// The exporting installation's own data must itself be a consistent snapshot; otherwise the
		// archive could never be restored. Fail the export rather than write an unusable backup.
		return Archive{}, nil, err
	}
	counts := map[string]int{"endpoints": len(sc.Endpoints), "users": len(sc.Users), "groups": len(sc.Groups), "agents": len(sc.Agents),
		"user_memberships": len(sc.UserMemberships), "agent_memberships": len(sc.AgentMemberships), "roles": len(sc.Roles), "selectors": len(sc.Selectors),
		"policies": len(sc.Policies), "addresses": len(sc.Addresses), "authenticators": len(sc.Authenticators), "agent_credentials": len(sc.AgentCredentials)}
	return a, counts, nil
}

// normalizeScope replaces nil slices by empty ones (so the JSON never differs between null and []).
func normalizeScope(s Scope) Scope {
	if s.Endpoints == nil {
		s.Endpoints = []EndpointRecord{}
	}
	if s.Users == nil {
		s.Users = []UserRecord{}
	}
	if s.Groups == nil {
		s.Groups = []GroupRecord{}
	}
	if s.Agents == nil {
		s.Agents = []AgentRecord{}
	}
	if s.UserMemberships == nil {
		s.UserMemberships = []UserMembershipRecord{}
	}
	if s.AgentMemberships == nil {
		s.AgentMemberships = []AgentMembershipRecord{}
	}
	if s.Roles == nil {
		s.Roles = []RoleRecord{}
	}
	if s.Selectors == nil {
		s.Selectors = []SelectorRecord{}
	}
	if s.Policies == nil {
		s.Policies = []PolicyRecord{}
	}
	if s.Addresses == nil {
		s.Addresses = []AddressRecord{}
	}
	if s.Authenticators == nil {
		s.Authenticators = []AuthenticatorRecord{}
	}
	if s.AgentCredentials == nil {
		s.AgentCredentials = []AgentCredentialRecord{}
	}
	sort.SliceStable(s.Endpoints, func(i, j int) bool { return s.Endpoints[i].ID < s.Endpoints[j].ID })
	return s
}

// Verified is an archive that passed every check that needs no storage: strict shape, versions,
// content digest, integrity tag (or the documented clean-mode downgrade), the envelope, and
// structural consistency. It is not an authorization: nothing in it is current or approved.
type Verified struct {
	archive    Archive
	payload    secretPayload
	provenance Provenance
	wiped      bool
}

// Wipe zeroes the plaintext credential material that opening a full archive produced (TOTP seeds, WebAuthn records,
// verifier and token hashes) and makes this value unusable for any further Restore. The caller calls it as soon as it is done
// with the archive. Go gives no promise about copies the runtime made, so this limits how long the secrets stay reachable
// from the application; it is not a memory-erasure guarantee. It is idempotent.
func (v *Verified) Wipe() {
	if v == nil {
		return
	}
	v.wiped = true
	for _, a := range v.payload.Authenticators {
		for _, b := range [][]byte{a.TOTPSeed, a.VerifierHash, a.PublicKey, a.ExternalCredentialID} {
			clear(b)
		}
	}
	for _, b := range v.payload.AgentCredentials {
		clear(b)
	}
	for _, b := range v.payload.WebauthnUsers {
		clear(b)
	}
	for _, b := range v.payload.WebauthnRecords {
		clear(b)
	}
}

func (v *Verified) BackupID() string               { return v.archive.BackupID }
func (v *Verified) Mode() Mode                     { return v.archive.Mode }
func (v *Verified) Provenance() Provenance         { return v.provenance }
func (v *Verified) CreatedAtInformational() string { return v.archive.CreatedAt }

// Verify performs the version/HMAC/envelope/consistency validation. It has NO side effects: a
// rejected archive changes nothing and never enters quarantine.
func (s *Service) Verify(raw []byte) (*Verified, error) {
	var a Archive
	if err := decodeStrict(raw, &a); err != nil {
		return nil, err
	}
	if a.Format != Format || a.SchemaVersion != ArchiveVersion || a.DatabaseSchemaVersion != store.SchemaVersion() {
		return nil, ErrUnsupportedVersion
	}
	if a.Mode != ModeFull && a.Mode != ModeClean {
		return nil, ErrMalformed
	}
	if !validID(a.BackupID) || len(a.MandataryVersion) == 0 || len(a.MandataryVersion) > 128 {
		return nil, ErrMalformed
	}
	if _, err := time.Parse(time.RFC3339, a.CreatedAt); err != nil {
		return nil, ErrMalformed
	}
	hmacSalt, err := base64.StdEncoding.Strict().DecodeString(a.HMACSalt)
	if err != nil || len(hmacSalt) != saltBytes {
		return nil, ErrMalformed
	}
	if (a.Mode == ModeFull) != (a.Secrets != nil) {
		return nil, ErrMalformed
	}
	canonical, err := a.canonical()
	if err != nil {
		return nil, ErrMalformed
	}
	if !equalB64(a.ContentDigest, digestOf(canonical)) {
		return nil, ErrIntegrity
	}
	key, err := s.repo.DeriveBackupKey(integrityInfo, hmacSalt)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(key)
	prov := ProvenanceAuthenticated
	if !equalB64(a.IntegrityHMAC, tagOf(key, canonical)) {
		if a.Mode == ModeFull {
			return nil, ErrIntegrity // wrong key and modified archive are the same, fixed answer
		}
		prov = ProvenanceUnauthenticated
	}
	if err := validateScope(a.Scope, a.Mode); err != nil {
		return nil, err
	}
	v := &Verified{archive: a, provenance: prov}
	if a.Mode == ModeFull {
		salt, err := base64.StdEncoding.Strict().DecodeString(a.Secrets.Salt)
		if err != nil || len(salt) != saltBytes {
			return nil, ErrMalformed
		}
		sk, err := s.repo.DeriveBackupKey(secretsInfo, salt)
		if err != nil {
			return nil, ErrUnavailable
		}
		defer clear(sk)
		if v.payload, err = openPayload(a, sk); err != nil {
			return nil, err
		}
		if err := checkPayload(a.Scope, v.payload); err != nil {
			return nil, err
		}
	}
	return v, nil
}

// checkPayload requires the sealed material to match the cleartext scope exactly: no credential
// without a record, no record without its material.
func checkPayload(sc Scope, p secretPayload) error {
	if len(p.Authenticators) != len(sc.Authenticators) || len(p.AgentCredentials) != len(sc.AgentCredentials) {
		return inconsistent("payload_mismatch")
	}
	kinds := map[string]string{}
	users := map[string]bool{}
	for _, a := range sc.Authenticators {
		sec, ok := p.Authenticators[a.ID]
		if !ok {
			return inconsistent("payload_mismatch")
		}
		kinds[a.ID] = a.Kind
		users[a.UserID] = true
		if a.Kind == "totp" && (len(sec.TOTPSeed) == 0 || len(sec.TOTPSeed) > 1024) {
			return inconsistent("payload_mismatch")
		}
		if sec.RetryCeiling < 1 || sec.RetryCeiling > 100 || sec.CreatedAt < 0 || len(sec.VerifierHash) > 4096 || len(sec.PublicKey) > 4096 || len(sec.ExternalCredentialID) > 1024 {
			return inconsistent("payload_mismatch")
		}
		if sec.MaxAssurance < 0 || sec.MaxAssurance > 2 {
			return inconsistent("payload_mismatch")
		}
	}
	for _, c := range sc.AgentCredentials {
		if h, ok := p.AgentCredentials[c.ID]; !ok || len(h) != 32 {
			return inconsistent("payload_mismatch")
		}
	}
	for id, handle := range p.WebauthnRecords {
		if kinds[id] != "webauthn" || len(handle) == 0 || len(handle) > 64*1024 {
			return inconsistent("payload_mismatch")
		}
	}
	for id, h := range p.WebauthnUsers {
		if !users[id] || len(h) != 32 {
			return inconsistent("payload_mismatch")
		}
	}
	return nil
}
