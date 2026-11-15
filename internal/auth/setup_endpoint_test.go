package auth

import "testing"

// P1.19 composition finding: the migration seeds the one local endpoint as `quarantined`, and nothing
// on a fresh installation ever made it effective, so no policy could ever target it outside tests that
// edit SQL by hand. The committed first-administrator enrollment is the deliberate, human-attended act
// that unlocks a fresh installation (UnlockInstallation, same transaction), so it also makes the seeded
// local endpoint a valid policy target at the new authority generation. It grants nothing by itself:
// no rule, credential or operation exists, the administrator role carries no container authority and
// self-protection must still be verified before any dispatch.

func TestFirstAdminCommitMakesTheSeededLocalEndpointAPolicyTargetOnFreshInstall(t *testing.T) {
	e := newSetupEnv(t)
	if r := e.ensure(); r.Outcome != "issued" {
		t.Fatalf("first start outcome %q", r.Outcome)
	}
	if e.text(`SELECT state FROM endpoints WHERE slug='local'`) != "quarantined" || e.scalar(`SELECT authority_generation FROM endpoints WHERE slug='local'`) != 0 {
		t.Fatal("a fresh installation must seed the local endpoint inactive")
	}
	_ = e.firstAdmin()
	if got := e.text(`SELECT state FROM endpoints WHERE slug='local'`); got != "active" {
		t.Fatalf("the local endpoint stayed %q after the first administrator committed", got)
	}
	if e.scalar(`SELECT e.authority_generation = c.authority_generation FROM endpoints e, installation_control c WHERE e.slug='local' AND c.singleton=1`) != 1 {
		t.Fatal("the endpoint must carry the installation's current authority generation")
	}
	// Activation is not authority: nothing grants an operation yet.
	for _, q := range []string{`SELECT count(*) FROM policies`, `SELECT count(*) FROM agents`, `SELECT count(*) FROM agent_credentials`, `SELECT count(*) FROM container_selectors`} {
		if e.scalar(q) != 0 {
			t.Fatalf("setup created authority: %s", q)
		}
	}
	// Only the local endpoint exists, and nothing but the fresh-install transition may have changed it.
	if e.scalar(`SELECT count(*) FROM endpoints`) != 1 {
		t.Fatal("unexpected endpoint rows")
	}
}

func TestSecondCompletionCannotReactivateOrRegressTheEndpoint(t *testing.T) {
	e := newSetupEnv(t)
	a := e.firstAdmin()
	e.exec(`UPDATE endpoints SET state='disabled' WHERE slug='local'`)
	if _, err := e.s.Complete(e.ctx(), a.session.Secret()); err == nil {
		t.Fatal("a second initial completion succeeded")
	}
	if got := e.text(`SELECT state FROM endpoints WHERE slug='local'`); got != "disabled" {
		t.Fatalf("a refused completion changed the endpoint: %q", got)
	}
}
