package authz

// SetAcquireSeamsForTest installs the deterministic AcquireLease stage barriers. It lives in
// a _test.go file, so it is compiled only into package tests and is not part of the
// production API. Call it before any concurrent use of the Authorizer.
func (a *Authorizer) SetAcquireSeamsForTest(beforeRegister, beforePublish func()) {
	a.acquireSeams = acquireSeams{beforeRegister: beforeRegister, beforePublish: beforePublish}
}
