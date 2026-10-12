'use strict'
const { test } = require('node:test')
const assert = require('node:assert')
const crypto = require('crypto')

const allowHost = require('../allow-host.js')
const createAuthorization = require('../authorization.js')
const { verifyHs256 } = createAuthorization
const { forwardHeaders } = require('../middleware.js')

const ALLOW = ['github.com', 'gitlab.com', 'bitbucket.org']

test('allows an exact allowlisted host', () => {
  assert.strictEqual(allowHost('github.com', ALLOW).ok, true)
})

test('allows a subdomain of an allowlisted host', () => {
  assert.strictEqual(allowHost('api.github.com', ALLOW).ok, true)
})

test('allows an allowlisted host with a port', () => {
  assert.strictEqual(allowHost('github.com:443', ALLOW).ok, true)
})

test('rejects a host that is not on the allowlist', () => {
  const v = allowHost('evil.example.com', ALLOW)
  assert.strictEqual(v.ok, false)
  assert.strictEqual(v.reason, 'not-allowed')
})

test('fails closed when the allowlist is empty', () => {
  const v = allowHost('github.com', [])
  assert.strictEqual(v.ok, false)
  assert.strictEqual(v.reason, 'no-allowlist')
})

test('a host that merely ends with the allowlist string is not allowed', () => {
  // notgithub.com must not match github.com
  assert.strictEqual(allowHost('notgithub.com', ALLOW).ok, false)
})

for (const target of [
  '169.254.169.254', // cloud metadata
  '127.0.0.1',
  '10.0.0.5',
  '172.16.0.1',
  '192.168.1.1',
  '100.64.0.1',
  '0.0.0.0',
  'localhost',
  'foo.localhost',
  '[::1]',
  '[fe80::1]',
  '[fd00::1]'
]) {
  test(`blocks internal/metadata target ${target} even if put on the allowlist`, () => {
    const v = allowHost(target, ALLOW.concat([target.replace(/[\[\]]/g, '')]))
    assert.strictEqual(v.ok, false)
    assert.strictEqual(v.reason, 'blocked-address')
  })
}

// Userinfo in the host segment must not fool the allowlist: fetch would dial the
// host after '@', not the allowlisted name before it (CWE-918).
for (const target of [
  'github.com:x@169.254.169.254',
  'github.com:x@evil.com',
  'github.com@169.254.169.254'
]) {
  test(`rejects userinfo authority ${target}`, () => {
    assert.strictEqual(allowHost(target, ALLOW).ok, false)
  })
}

// Private/local IPv6 ranges must be blocked across the whole CIDR range, not
// just the lowest address, and for IPv4-mapped forms in either notation.
for (const target of [
  '[fe80::1]',   // link-local, low end of fe80::/10
  '[fe81::1]',   // link-local, mid range (missed by a bare "fe80" prefix check)
  '[febf::1]',   // link-local, high end of fe80::/10
  '[fd00::1]',   // unique-local fc00::/7
  '[::ffff:7f00:1]',     // IPv4-mapped 127.0.0.1 in hex notation
  '[::ffff:a9fe:a9fe]',  // IPv4-mapped 169.254.169.254 (metadata) in hex notation
  '[::ffff:127.0.0.1]'   // IPv4-mapped 127.0.0.1 in dotted notation
]) {
  test(`blocks internal IPv6 target ${target} even if put on the allowlist`, () => {
    const v = allowHost(target, ALLOW.concat([target.replace(/[\[\]]/g, '')]))
    assert.strictEqual(v.ok, false)
    assert.strictEqual(v.reason, 'blocked-address')
  })
}

test('allows a public IPv6 literal outside the blocked ranges when allowlisted', () => {
  assert.strictEqual(allowHost('[2606:4700::1111]', ALLOW.concat(['2606:4700::1111'])).ok, true)
})

// --- upstream header forwarding ---

test('forwards allowlisted headers and the git credential header upstream', () => {
  const out = forwardHeaders({ authorization: 'Bearer gitcreds', accept: 'application/json' })
  assert.strictEqual(out.authorization, 'Bearer gitcreds')
  assert.strictEqual(out.accept, 'application/json')
})

test('does not forward the proxy auth header (x-authorization) upstream', () => {
  const out = forwardHeaders({ 'x-authorization': 'Bearer proxytoken', authorization: 'Bearer gitcreds' })
  assert.strictEqual(out['x-authorization'], undefined)
  assert.strictEqual(out.authorization, 'Bearer gitcreds')
})

// --- authorization (HS256 JWT) ---

function makeToken (payload, secret, alg = 'HS256') {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  const head = b64({ alg, typ: 'JWT' })
  const body = b64(payload)
  const sig = crypto.createHmac('sha256', secret).update(head + '.' + body).digest('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  return `${head}.${body}.${sig}`
}

test('verifyHs256 accepts a valid token', () => {
  assert.strictEqual(verifyHs256(makeToken({ sub: 'u1' }, 'topsecret'), 'topsecret'), true)
})

test('verifyHs256 rejects a token signed with another secret', () => {
  assert.strictEqual(verifyHs256(makeToken({ sub: 'u1' }, 'other'), 'topsecret'), false)
})

test('verifyHs256 rejects an expired token', () => {
  const exp = Math.floor(Date.now() / 1000) - 60
  assert.strictEqual(verifyHs256(makeToken({ sub: 'u1', exp }, 'topsecret'), 'topsecret'), false)
})

test('verifyHs256 rejects a malformed token', () => {
  assert.strictEqual(verifyHs256('not.a.jwt', 'topsecret'), false)
})

test('authorization is a no-op when no secret is configured', () => {
  const mw = createAuthorization({})
  let called = false
  mw({ headers: {} }, {}, () => { called = true })
  assert.strictEqual(called, true)
})

test('authorization passes a request bearing a valid token', () => {
  const mw = createAuthorization({ secret: 'topsecret' })
  let called = false
  const token = makeToken({ sub: 'u1' }, 'topsecret')
  mw({ headers: { 'x-authorization': `Bearer ${token}` } }, {}, () => { called = true })
  assert.strictEqual(called, true)
})

test('authorization rejects a request without a valid token', () => {
  const mw = createAuthorization({ secret: 'topsecret' })
  let nextCalled = false
  let status = null
  const res = {
    statusCode: 200,
    setHeader () {},
    getHeader () {},
    end (body) { status = this.statusCode }
  }
  mw({ headers: {} }, res, () => { nextCalled = true })
  assert.strictEqual(nextCalled, false)
  assert.strictEqual(status, 401)
})
