package store_test

import "testing"

func TestCredentialNullMaterialAndAccountBinding(t *testing.T) {
	db, _ := fixture(t)
	principals(t, db)
	exec(t, db, `INSERT INTO authenticators(id,user_id,kind) VALUES ('code','u1','recovery_code'),('other','u2','webauthn')`)
	rejects(t, db, `UPDATE authenticators SET state='active',credential_generation=1,bound_at=1 WHERE id='code'`)
	exec(t, db, `INSERT INTO sessions(id,user_id,secret_hash,purpose,created_at,expires_at,last_activity_at) VALUES ('s1','u1',zeroblob(32),'normal',1,100,1)`)
	rejects(t, db, `INSERT INTO session_authenticators(session_id,authenticator_id,user_id) VALUES ('s1','other','u1')`)
	rejects(t, db, `INSERT INTO auth_challenges(id,user_id,session_id,purpose,challenge_hash,issued_at,expires_at) VALUES ('bad','u2','s1','webauthn_assertion',zeroblob(32),1,100)`)
	exec(t, db, `INSERT INTO auth_challenges(id,user_id,session_id,purpose,challenge_hash,issued_at,expires_at) VALUES ('ok','u1','s1','webauthn_assertion',zeroblob(32),1,100)`)
	exec(t, db, `UPDATE auth_challenges SET consumed_at=2 WHERE id='ok'`)
	rejects(t, db, `UPDATE auth_challenges SET consumed_at=NULL WHERE id='ok'`)
}
