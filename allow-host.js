'use strict'
const net = require('net')

// Parse the "host[:port]" first path segment into a bare, lower-cased hostname.
// Handles IPv4, bracketed IPv6 ([::1]:443) and plain IPv6 literals.
function parseHost (pathdomain) {
  if (!pathdomain) return ''
  let host = pathdomain
  const bracketed = host.match(/^\[([^\]]+)\](?::\d+)?$/)
  if (bracketed) return bracketed[1].toLowerCase()
  // host:port where host is a name or IPv4 (exactly one colon)
  if (host.split(':').length === 2) {
    host = host.split(':')[0]
  }
  return host.toLowerCase()
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

function isBlockedIpv6 (ip) {
  const a = ip.toLowerCase()
  if (a === '::1' || a === '::') return true  // loopback / unspecified
  if (a.startsWith('fe80')) return true       // link-local fe80::/10
  if (a.startsWith('fc') || a.startsWith('fd')) return true // unique-local fc00::/7
  const mapped = a.match(/(?:::ffff:)(\d+\.\d+\.\d+\.\d+)$/)
  if (mapped) return isBlockedIpv4(mapped[1])
  return false
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
