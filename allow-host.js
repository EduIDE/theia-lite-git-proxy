'use strict'
const net = require('net')

// Parse the "host[:port]" first path segment into the bare, lower-cased hostname
// that the upstream URL parser (and therefore `fetch`) will actually dial.
// Accepts only "name[:port]" or "[ipv6][:port]" and rejects userinfo (user@host)
// or any other URL authority syntax. Without this, a segment like
// "github.com:x@169.254.169.254" would split to the allowlisted "github.com"
// while `fetch` dials 169.254.169.254, bypassing the allowlist (CWE-918).
function parseHost (pathdomain) {
  if (!pathdomain) return ''
  if (!/^(?:[a-z0-9.-]+|\[[0-9a-f:.]+\])(?::\d{1,5})?$/i.test(pathdomain)) return ''
  let u
  try { u = new URL(`https://${pathdomain}/`) } catch (e) { return '' }
  if (u.username || u.password) return ''
  return u.hostname.replace(/^\[|\]$/g, '').toLowerCase()
}

function isBlockedIpv4 (ip) {
  const o = ip.split('.').map(Number)
  if (o[0] === 0) return true                                // 0.0.0.0/8
  if (o[0] === 127) return true                              // loopback 127.0.0.0/8
  if (o[0] === 10) return true                               // private 10.0.0.0/8
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true  // private 172.16.0.0/12
  if (o[0] === 192 && o[1] === 168) return true              // private 192.168.0.0/16
  if (o[0] === 169 && o[1] === 254) return true              // link-local 169.254.0.0/16 (incl. metadata 169.254.169.254)
  if (o[0] === 100 && o[1] >= 64 && o[1] <= 127) return true // CGNAT 100.64.0.0/10
  return false
}

// CIDR-aware block list for the full private / local IPv6 ranges, so the whole
// fe80::/10 link-local range (not just fe80::) and fc00::/7 unique-local range
// are covered.
const ipv6BlockList = new net.BlockList()
ipv6BlockList.addAddress('::1', 'ipv6')        // loopback
ipv6BlockList.addAddress('::', 'ipv6')         // unspecified
ipv6BlockList.addSubnet('fe80::', 10, 'ipv6')  // link-local fe80::/10
ipv6BlockList.addSubnet('fc00::', 7, 'ipv6')   // unique-local fc00::/7

// Extract the embedded IPv4 address from an IPv4-mapped IPv6 literal, in both
// the dotted "::ffff:1.2.3.4" and hexadecimal "::ffff:7f00:1" forms that
// net.isIPv6 accepts. Returns null when the address is not IPv4-mapped.
function mappedIpv4 (a) {
  const m = a.match(/^::ffff:(.+)$/)
  if (!m) return null
  const rest = m[1]
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(rest)) return rest
  const hex = rest.match(/^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/)
  if (!hex) return null
  const hi = parseInt(hex[1], 16)
  const lo = parseInt(hex[2], 16)
  return [(hi >> 8) & 0xff, hi & 0xff, (lo >> 8) & 0xff, lo & 0xff].join('.')
}

function isBlockedIpv6 (ip) {
  const a = ip.toLowerCase()
  // IPv4-mapped addresses reach an IPv4 host, so apply the IPv4 rules to them.
  const embedded = mappedIpv4(a)
  if (embedded) return isBlockedIpv4(embedded)
  return ipv6BlockList.check(a, 'ipv6')
}

// Hosts that must never be proxied to, regardless of the allowlist: loopback
// names and private / link-local / metadata literal IP addresses.
function isBlockedHost (host) {
  if (!host) return true
  if (host === 'localhost' || host.endsWith('.localhost')) return true
  if (net.isIPv4(host)) return isBlockedIpv4(host)
  if (net.isIPv6(host)) return isBlockedIpv6(host)
  return false
}

// A host is allowed when it matches an allowlist entry exactly or is a
// subdomain of one (e.g. "github.com" allows "api.github.com").
function hostAllowed (host, allowedHosts) {
  return allowedHosts.some((a) => host === a || host.endsWith('.' + a))
}

// Decide whether the proxy may reach `pathdomain` (the attacker-controlled host
// segment of the request path). Blocked literal addresses are rejected first,
// then the host must appear on the configured allowlist. An empty allowlist
// fails closed. Returns { ok, reason } where reason is one of
// 'blocked-address', 'no-allowlist', 'not-allowed'.
//
// Note: this validates the literal host only. It does NOT resolve DNS, so a
// hostname that an attacker makes resolve to a private IP (DNS rebinding) is
// out of scope here and would need resolve-then-pin protection.
module.exports = function allowHost (pathdomain, allowedHosts = []) {
  const host = parseHost(pathdomain)
  if (isBlockedHost(host)) return { ok: false, reason: 'blocked-address' }
  if (!allowedHosts || allowedHosts.length === 0) return { ok: false, reason: 'no-allowlist' }
  if (!hostAllowed(host, allowedHosts)) return { ok: false, reason: 'not-allowed' }
  return { ok: true }
}

module.exports.parseHost = parseHost
module.exports.isBlockedHost = isBlockedHost
module.exports.hostAllowed = hostAllowed
