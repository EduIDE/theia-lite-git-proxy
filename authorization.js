'use strict'
const crypto = require('crypto')
const { send } = require('micro')

function b64url (buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

// Verify a compact HS256 JWT against `secret`. Returns true only for a
// well-formed, correctly signed and unexpired token. No external dependency so
// the proxy stays dependency-light; swap in a full JWT library if you need
// other algorithms or claim validation.
function verifyHs256 (token, secret) {
  const parts = token.split('.')
  if (parts.length !== 3) return false
  const [h, p, sig] = parts

  let header
  try { header = JSON.parse(Buffer.from(h, 'base64')) } catch (e) { return false }
  if (!header || header.alg !== 'HS256') return false

  const expected = b64url(crypto.createHmac('sha256', secret).update(h + '.' + p).digest())
  const a = Buffer.from(sig)
  const b = Buffer.from(expected)
  if (a.length !== b.length) return false
  if (!crypto.timingSafeEqual(a, b)) return false

  let payload
  try { payload = JSON.parse(Buffer.from(p, 'base64')) } catch (e) { return false }
  if (payload.exp && Math.floor(Date.now() / 1000) > payload.exp) return false

  return true
}

// Build the `authorization` middleware hook the README documents. When
// GIT_PROXY_AUTH_SECRET is set, only requests carrying a valid HS256 JWT are
// proxied; otherwise authentication is a no-op (the host allowlist remains the
// always-on control). Proxied git requests already use the Authorization header
// for git credentials, so the proxy's own token is read from X-Authorization by
// default (override with GIT_PROXY_AUTH_HEADER).
module.exports = function createAuthorization (opts = {}) {
  const secret = opts.secret || process.env.GIT_PROXY_AUTH_SECRET
  if (!secret) {
    return function noAuth (_req, _res, next) { next() }
  }
  const header = (opts.header || process.env.GIT_PROXY_AUTH_HEADER || 'x-authorization').toLowerCase()
  return function requireJwt (req, res, next) {
    const raw = req.headers[header]
    const token = raw && String(raw).replace(/^Bearer /i, '')
    if (token && verifyHs256(token, secret)) {
      return next()
    }
    return send(res, 401, 'Unable to authenticate with the git proxy')
  }
}

module.exports.verifyHs256 = verifyHs256
