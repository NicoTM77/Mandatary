package store_test

import (
	"database/sql"
	"testing"
)

// P1.10 schema integrity: the credential lifecycle rules the administrative
// service relies on are also enforced by SQLite itself, so no other writer
// (restore import, repair tooling, a future adapter) can resurrect a revoked or
// rotated-out token, extend an overlap window, mutate a stored verifier or leave
// an active credential behind a non-active agent.

func credentialSchema(t *testing.T) *sql.DB {
	t.Helper()
	db, _ := fixture(t)
	exec(t, db, "UPDATE installation_control SET credential_generation=1,session_generation=1,authority_generation=1,restore_generation=1,restore_quarantined=0")
	exec(t, db, "INSERT INTO users(id,username,state,credential_generation,authority_generation) VALUES ('u1','alice','active',1,1)")
	exec(t, db, "INSERT INTO agents(id,name,owner_user_id,state,credential_generation,authority_generation) VALUES ('a1','active-agent','u1','active',1,1)")
	exec(t, db, "INSERT INTO agents(id,name,owner_user_id) VALUES ('a2','quarantined-agent','u1')")
	return db
}

func hashOf(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestRevokedAgentCredentialIsFinal(t *testing.T) {
	db := credentialSchema(t)
	exec(t, db, "INSERT INTO agent_credentials(id,agent_id,token_hash,display_prefix,issued_at,expires_at,credential_generation,state) VALUES ('c1','a1',?,'mdt_c1',100,900,1,'active')", hashOf(1))
	exec(t, db, "UPDATE agent_credentials SET state='revoked',revoked_at=150 WHERE id='c1'")
	rejects(t, db, "UPDATE agent_credentials SET state='active',revoked_at=NULL WHERE id='c1'")
	rejects(t, db, "UPDATE agent_credentials SET state='quarantined',revoked_at=NULL WHERE id='c1'")
	rejects(t, db, "UPDATE agent_credentials SET revoked_at=160 WHERE id='c1'")
	rejects(t, db, "UPDATE agent_credentials SET credential_generation=2 WHERE id='c1'")
	rejects(t, db, "UPDATE agent_credentials SET rotation_overlap_until=500 WHERE id='c1'")
	if integer(t, db, "SELECT count(*) FROM agent_credentials WHERE id='c1' AND state='revoked' AND revoked_at=150") != 1 {
		t.Fatal("revoked credential changed")
	}
}

func TestAgentCredentialVerifierAndWindowAreImmutable(t *testing.T) {
	db := credentialSchema(t)
	exec(t, db, "INSERT INTO agents(id,name,owner_user_id,state,credential_generation,authority_generation) VALUES ('a3','other','u1','active',1,1)")
	exec(t, db, "INSERT INTO agent_credentials(id,agent_id,token_hash,display_prefix,issued_at,expires_at,credential_generation,state) VALUES ('c1','a1',?,'mdt_c1',100,900,1,'active')", hashOf(1))
	for name, statement := range map[string]string{
		"hash":         "UPDATE agent_credentials SET token_hash=zeroblob(32) WHERE id='c1'",
		"agent":        "UPDATE agent_credentials SET agent_id='a3' WHERE id='c1'",
		"issued":       "UPDATE agent_credentials SET issued_at=50 WHERE id='c1'",
		"expiry":       "UPDATE agent_credentials SET expires_at=99999 WHERE id='c1'",
		"unexpiring":   "UPDATE agent_credentials SET expires_at=NULL,nonexpiring_approved=1 WHERE id='c1'",
		"display name": "UPDATE agent_credentials SET display_prefix='mdt_zz' WHERE id='c1'",
	} {
		t.Run(name, func(t *testing.T) { rejects(t, db, statement) })
	}
}

func TestRotationOverlapCanOnlyShrink(t *testing.T) {
	db := credentialSchema(t)
	exec(t, db, "INSERT INTO agent_credentials(id,agent_id,token_hash,display_prefix,issued_at,expires_at,credential_generation,state) VALUES ('c1','a1',?,'mdt_c1',100,900,1,'active')", hashOf(1))
	exec(t, db, "UPDATE agent_credentials SET rotation_overlap_until=400 WHERE id='c1'")
	rejects(t, db, "UPDATE agent_credentials SET rotation_overlap_until=401 WHERE id='c1'")
	rejects(t, db, "UPDATE agent_credentials SET rotation_overlap_until=NULL WHERE id='c1'")
	exec(t, db, "UPDATE agent_credentials SET rotation_overlap_until=399 WHERE id='c1'")
	if integer(t, db, "SELECT rotation_overlap_until FROM agent_credentials WHERE id='c1'") != 399 {
		t.Fatal("overlap did not shrink")
	}
}

func TestAgentCredentialHashIsUniqueAndFixedLength(t *testing.T) {
	db := credentialSchema(t)
	exec(t, db, "INSERT INTO agent_credentials(id,agent_id,token_hash,display_prefix,issued_at,expires_at,credential_generation,state) VALUES ('c1','a1',?,'mdt_c1',100,900,1,'active')", hashOf(1))
	rejects(t, db, "INSERT INTO agent_credentials(id,agent_id,token_hash,display_prefix,issued_at,expires_at,credential_generation,state) VALUES ('c2','a1',?,'mdt_c2',100,900,1,'active')", hashOf(1))
	rejects(t, db, "INSERT INTO agent_credentials(id,agent_id,token_hash,display_prefix,issued_at,expires_at) VALUES ('c3','a1',?,'mdt_c3',100,900)", []byte("short"))
	// Expiry is mandatory unless the explicit non-expiring approval flag is set.
	rejects(t, db, "INSERT INTO agent_credentials(id,agent_id,token_hash,display_prefix,issued_at) VALUES ('c4','a1',?,'mdt_c4',100)", hashOf(4))
}
