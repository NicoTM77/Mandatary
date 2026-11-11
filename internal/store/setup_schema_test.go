package store_test

import "testing"

const insertToken = `INSERT INTO setup_tokens(purpose,installation_id,build_identity,digest,state,issued_at,expires_at) VALUES ('initial_setup',randomblob(32),'b',randomblob(32),'available',1000,2800)`

// P1.09 storage invariants that do not depend on application code being correct.
func TestSetupTokenSchemaInvariants(t *testing.T) {
	db, _ := fixture(t)
	exec(t, db, insertToken)
	// Absolute expiry and identity are immutable; lifetime is capped at 30 minutes.
	rejects(t, db, `UPDATE setup_tokens SET expires_at=expires_at+1`)
	rejects(t, db, `UPDATE setup_tokens SET issued_at=issued_at-1`)
	rejects(t, db, `UPDATE setup_tokens SET digest=randomblob(32)`)
	rejects(t, db, `UPDATE setup_tokens SET purpose='mfa_reset'`)
	rejects(t, db, `INSERT INTO setup_tokens(purpose,installation_id,build_identity,digest,state,issued_at,expires_at) VALUES ('initial_setup',randomblob(32),'b',randomblob(32),'pending',1000,2801)`)
	rejects(t, db, `INSERT INTO setup_tokens(purpose,installation_id,build_identity,digest,state,issued_at,expires_at) VALUES ('initial_setup',randomblob(32),'b',randomblob(31),'pending',1000,1500)`)
	// One live generation per purpose and target.
	rejects(t, db, `INSERT INTO setup_tokens(purpose,installation_id,build_identity,digest,state,issued_at,expires_at) VALUES ('initial_setup',randomblob(32),'b',randomblob(32),'available',1000,1500)`)
	// States only move forward; consumed/revoked are terminal; history is retained.
	rejects(t, db, `UPDATE setup_tokens SET state='retrieved',claimed_at=1,retrieved_at=1`) // skips 'claimed'
	exec(t, db, `UPDATE setup_tokens SET state='claimed',claimed_at=1001`)
	exec(t, db, `UPDATE setup_tokens SET state='retrieved',retrieved_at=1002`)
	exec(t, db, `UPDATE setup_tokens SET state='consumed',consumed_at=1003`)
	rejects(t, db, `UPDATE setup_tokens SET state='available'`)
	rejects(t, db, `UPDATE setup_tokens SET state='revoked',revoked_at=1,revoke_reason='rotated'`)
	rejects(t, db, `DELETE FROM setup_tokens`)
	// An mfa_reset generation needs a target and the recorded risk acknowledgement.
	rejects(t, db, `INSERT INTO setup_tokens(purpose,installation_id,build_identity,digest,state,issued_at,expires_at) VALUES ('mfa_reset',randomblob(32),'b',randomblob(32),'pending',1000,1500)`)
	exec(t, db, `INSERT INTO users(id,username) VALUES ('u1','alice')`)
	rejects(t, db, `INSERT INTO setup_tokens(purpose,target_user_id,installation_id,build_identity,digest,state,issued_at,expires_at,risk_acknowledged) VALUES ('mfa_reset','u1',randomblob(32),'b',randomblob(32),'pending',1000,1500,0)`)
	exec(t, db, `INSERT INTO setup_tokens(purpose,target_user_id,installation_id,build_identity,digest,state,issued_at,expires_at,risk_acknowledged) VALUES ('mfa_reset','u1',randomblob(32),'b',randomblob(32),'pending',1000,1500,1)`)
	rejects(t, db, `INSERT INTO setup_tokens(purpose,installation_id,build_identity,digest,state,issued_at,expires_at,replace_password) VALUES ('initial_setup',randomblob(32),'b',randomblob(32),'pending',1000,1500,1)`)
}

func TestSetupSessionIsBoundToItsConsumedTokenAndExpiry(t *testing.T) {
	db, _ := fixture(t)
	exec(t, db, insertToken)
	// Not consumed yet: no session can exist.
	rejects(t, db, `INSERT INTO setup_sessions(id,token_id,purpose,secret_hash,created_at,expires_at) VALUES (hex(randomblob(32)),1,'initial_setup',randomblob(32),1100,2800)`)
	exec(t, db, `UPDATE setup_tokens SET state='claimed',claimed_at=1001`)
	exec(t, db, `UPDATE setup_tokens SET state='retrieved',retrieved_at=1002`)
	exec(t, db, `UPDATE setup_tokens SET state='consumed',consumed_at=1100`)
	// The session must carry the token's ORIGINAL absolute expiry, not a later one.
	rejects(t, db, `INSERT INTO setup_sessions(id,token_id,purpose,secret_hash,created_at,expires_at) VALUES (hex(randomblob(32)),1,'initial_setup',randomblob(32),1100,2799)`)
	rejects(t, db, `INSERT INTO setup_sessions(id,token_id,purpose,secret_hash,created_at,expires_at) VALUES (hex(randomblob(32)),1,'initial_setup',randomblob(32),2800,2800)`)
	rejects(t, db, `INSERT INTO setup_sessions(id,token_id,purpose,secret_hash,created_at,expires_at) VALUES (hex(randomblob(32)),1,'mfa_reset',randomblob(32),1100,2800)`)
	exec(t, db, `INSERT INTO setup_sessions(id,token_id,purpose,secret_hash,created_at,expires_at) VALUES (hex(randomblob(32)),1,'initial_setup',randomblob(32),1100,2800)`)
	// Exactly one session per consumed token: a database invariant.
	rejects(t, db, `INSERT INTO setup_sessions(id,token_id,purpose,secret_hash,created_at,expires_at) VALUES (hex(randomblob(32)),1,'initial_setup',randomblob(32),1101,2800)`)
	rejects(t, db, `UPDATE setup_sessions SET expires_at=2801`)
	rejects(t, db, `UPDATE setup_sessions SET token_id=2`)
	// A setup session is not a login session: it lives in a separate table that the
	// normal session verifier never reads.
	if integer(t, db, `SELECT count(*) FROM sessions`) != 0 {
		t.Fatal("a setup session appeared as a normal session")
	}
}

func TestSetupStateIsMonotonic(t *testing.T) {
	db, _ := fixture(t)
	if integer(t, db, `SELECT count(*) FROM setup_state`) != 1 {
		t.Fatal("setup_state must be a singleton")
	}
	rejects(t, db, `INSERT INTO setup_state(singleton) VALUES (2)`)
	exec(t, db, `UPDATE setup_state SET initial_issued=1,clock_high_water=500`)
	rejects(t, db, `UPDATE setup_state SET initial_issued=0`)
	rejects(t, db, `UPDATE setup_state SET clock_high_water=499`)
	exec(t, db, `UPDATE setup_state SET completed_at=600`)
	rejects(t, db, `UPDATE setup_state SET completed_at=NULL`)
	rejects(t, db, `UPDATE setup_state SET completed_at=601`)
	if integer(t, db, `SELECT count(*) FROM setup_attempts`) != 3 {
		t.Fatal("one attempt counter per purpose expected")
	}
	rejects(t, db, `UPDATE setup_attempts SET failed=101`)
}
