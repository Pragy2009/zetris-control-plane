const {test} = require('node:test');
const assert = require('node:assert/strict');
const {createServer} = require('./server');

test('gateway identity is required, escaped, and rendered once without leaking session IDs', async t => {
  const server = createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const base = `http://127.0.0.1:${server.address().port}`;
  assert.equal((await fetch(base + '/healthz')).status, 200);
  assert.equal((await fetch(base)).status, 403);
  for (const user of ['admin-user', 'dev-user', 'viewer-user', '<script>alert(1)</script>{{HOST}}$&']) {
    const response = await fetch(base, {headers: {'x-tenant-id': 'ztna', 'x-current-user': user, 'x-session-id': 'private-session-marker'}});
    const page = await response.text();
    assert.equal(response.status, 200);
    assert.ok(response.headers.get('content-security-policy'));
    assert.ok(!page.includes('<script>'));
    assert.ok(!page.includes('private-session-marker'));
    if (user.includes('<')) assert.ok(page.includes('&lt;script&gt;alert(1)&lt;/script&gt;{{HOST}}$&amp;'));
    else assert.ok(page.includes(`Welcome, ${user}`));
  }
  assert.equal((await fetch(base, {method: 'POST'})).status, 405);
});
