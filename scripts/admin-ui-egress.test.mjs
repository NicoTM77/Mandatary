import assert from 'node:assert/strict';
import test from 'node:test';
import { allowsAppRequest, appOrigin } from '../web/tests/admin-ui-lib.mjs';

// The admin-UI browser harness lets the page reach only the exact fixture origin and a closed list of routes. The
// P1.17 policy-administration routes are in that list by method and shape; everything else stays closed. Synthetic
// loopback origin; no server is contacted.

const origin = appOrigin('https://example.invalid:43123');
const allowed = (path, method = 'GET') => allowsAppRequest(origin, new URL(path, origin).href, method);

test('policy lists are readable by GET only and documents are the four exact routes', () => {
  for (const route of ['users', 'groups', 'agents', 'rules']) {
    assert.equal(allowed(`/api/v1/admin/policy/${route}`), true, route);
    assert.equal(allowed(`/api/v1/admin/policy/${route}`, 'POST') && route !== 'rules', false, `${route} is not writable by POST`);
  }
  for (const route of ['/policy', '/policy/users', '/policy/groups', '/policy/agents']) assert.equal(allowed(route), true, route);
  for (const route of ['/policy/', '/policy/x', '/policy/rules', '/Policy']) assert.equal(allowed(route), false, route);
});

test('policy commands are allowed only with the exact method and shape', () => {
  const yes = [
    ['POST', '/api/v1/admin/users'],
    ['POST', '/api/v1/admin/groups'],
    ['POST', '/api/v1/admin/agents'],
    ['POST', '/api/v1/admin/users/u-1/disable'],
    ['POST', '/api/v1/admin/groups/g-1/enable'],
    ['POST', '/api/v1/admin/agents/a-1/enable'],
    ['POST', '/api/v1/admin/policy/rules'],
    ['POST', '/api/v1/admin/policy/rules/preview'],
    ['POST', '/api/v1/admin/policy/rules/r-1/disable'],
    ['PUT', '/api/v1/admin/groups/g-1/members/agent/a-1'],
    ['PUT', '/api/v1/admin/agents/a-1/owner'],
    ['PUT', '/api/v1/admin/policy/rules/r-1'],
    ['DELETE', '/api/v1/admin/groups/g-1'],
    ['DELETE', '/api/v1/admin/groups/g-1/members/user/u-1'],
    ['DELETE', '/api/v1/admin/policy/rules/r-1'],
  ];
  for (const [method, path] of yes) assert.equal(allowed(path, method), true, `${method} ${path}`);
  const no = [
    ['DELETE', '/api/v1/admin/users/u-1'], // users are never deleted
    ['DELETE', '/api/v1/admin/agents/a-1'], // nor agents
    ['PATCH', '/api/v1/admin/policy/rules/r-1'],
    ['PUT', '/api/v1/admin/users/u-1/disable'],
    ['POST', '/api/v1/admin/policy/rules/r-1'],
    ['POST', '/api/v1/admin/users/u 1/disable'],
    ['POST', '/api/v1/admin/policy/roles'],
    ['POST', '/api/v1/admin/users/u-1/role'],
    ['PUT', '/api/v1/admin/groups/g-1/members/role/x'],
    ['DELETE', '/api/v1/admin/policy/rules'],
    ['GET', '/api/v1/admin/policy/rules/r-1'],
    ['POST', '/api/v1/endpoints/local/containers/c/start'],
  ];
  for (const [method, path] of no) assert.equal(allowed(path, method), false, `${method} ${path}`);
  assert.equal(allowed('/api/v1/admin/policy/rules?x=1', 'GET'), false, 'no query string');
  assert.equal(allowsAppRequest(origin, 'https://evil.invalid/api/v1/admin/policy/rules', 'GET'), false, 'only the fixture origin');
});
