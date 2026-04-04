/**
 * Bitmask serialization for Permzplus permissions.
 *
 * Converts a user's effective permission set into a compact base64url string
 * that can be stored in a cookie, passed as a prop, or embedded in a JWT —
 * and decoded client-side / in Edge middleware without the full 2 KB engine.
 *
 * @example
 * ```ts
 * // Server — at login or in a Server Action
 * import { toBitmask, fromBitmask } from 'permzplus/bitmask'
 *
 * const bitmask = toBitmask(policy, user.role)
 * // store in cookie: res.cookie('permz', bitmask, { httpOnly: true, sameSite: 'strict' })
 *
 * // Client or Edge middleware — decode and check locally
 * const perms = fromBitmask(bitmask)
 * perms.can('posts:read')   // true / false — no server round-trip
 * perms.canAll(['posts:read', 'posts:write'])
 * ```
 */

import type { IPolicyEngine } from './types'
import { matchesPermission } from './permissions'

// ---------------------------------------------------------------------------
// Internal encoding helpers
// ---------------------------------------------------------------------------

/** Separator character — must not appear in valid permission strings. */
const SEP = '|'

/**
 * Encode a plain-ASCII string to base64url. Safe in cookies and query strings.
 * Uses the WHATWG `btoa` global available in Node 18+, Edge Runtime, and browsers.
 * Permission strings are guaranteed ASCII-safe by the PERMISSION_PATTERN regex.
 */
function toBase64Url(s: string): string {
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** Decode a base64url string back to plain ASCII. */
function fromBase64Url(s: string): string {
  const padded = s.replace(/-/g, '+').replace(/_/g, '/')
  const rem = padded.length % 4
  return atob(rem === 0 ? padded : padded + '='.repeat(4 - rem))
}

// ---------------------------------------------------------------------------
// PermissionBitmask
// ---------------------------------------------------------------------------

/**
 * Decoded permission set returned by `fromBitmask()`.
 *
 * All checks run locally in O(n) time — no server round-trips, no engine import.
 * Wildcard patterns (`*`, `resource:*`) are honoured exactly as the full engine does.
 */
export interface PermissionBitmask {
  /** Returns `true` when the encoded permission set grants the given permission. */
  can(permission: string): boolean
  /** Returns `true` when the encoded permission set does NOT grant the given permission. */
  cannot(permission: string): boolean
  /** Returns `true` when ALL of the given permissions are granted. */
  canAll(permissions: string[]): boolean
  /** Returns `true` when AT LEAST ONE of the given permissions is granted. */
  canAny(permissions: string[]): boolean
  /** The raw base64url string this object was decoded from. Pass it to cookies / props. */
  readonly raw: string
}

class PermissionBitmaskImpl implements PermissionBitmask {
  private readonly _perms: Set<string>
  readonly raw: string

  constructor(perms: string[], raw: string) {
    this._perms = new Set(perms)
    this.raw = raw
  }

  can(permission: string): boolean {
    // Fast path: exact match or '*' wildcard
    if (this._perms.has('*') || this._perms.has(permission)) return true
    // Check resource:* wildcard
    const colon = permission.indexOf(':')
    if (colon !== -1 && this._perms.has(`${permission.slice(0, colon)}:*`)) return true
    // Full pattern scan (handles any stored wildcards matching the queried permission)
    for (const pattern of this._perms) {
      if (matchesPermission(permission, pattern)) return true
    }
    return false
  }

  cannot(permission: string): boolean {
    return !this.can(permission)
  }

  canAll(permissions: string[]): boolean {
    for (let i = 0; i < permissions.length; i++) {
      if (!this.can(permissions[i])) return false
    }
    return true
  }

  canAny(permissions: string[]): boolean {
    for (let i = 0; i < permissions.length; i++) {
      if (this.can(permissions[i])) return true
    }
    return false
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Encodes a user's effective permissions into a compact base64url string.
 *
 * The resulting string is safe for use in:
 * - HTTP cookies (`Set-Cookie`)
 * - Query parameters (no `+`, `/`, or `=` characters)
 * - JWTs / session payloads
 * - React props passed from Server Components to Client Components
 *
 * @param engine - The `PolicyEngine` (or any `IPolicyEngine`) to query.
 * @param role   - The user's role or array of roles. Multi-role sets are unioned.
 * @returns A base64url string. Pass to `fromBitmask()` to decode.
 *
 * @example
 * ```ts
 * const bitmask = toBitmask(policy, 'EDITOR')
 * // → "cG9zdHM6cmVhZHxwb3N0czp3cml0ZQ"
 *
 * // Multi-role
 * const bitmask = toBitmask(policy, ['EDITOR', 'MODERATOR'])
 * ```
 */
export function toBitmask(engine: IPolicyEngine, role: string | string[]): string {
  const roles = Array.isArray(role) ? role : [role]
  const union = new Set<string>()

  for (const r of roles) {
    try {
      for (const perm of engine.getPermissions(r)) {
        union.add(perm)
      }
    } catch {
      // Unknown / empty role — skip silently
    }
  }

  const sorted = Array.from(union).sort()
  const raw = toBase64Url(sorted.join(SEP))
  return raw
}

/**
 * Decodes a base64url bitmask string produced by `toBitmask()` into a
 * `PermissionBitmask` object that can run permission checks locally.
 *
 * This function is designed for use in:
 * - Next.js middleware (Edge Runtime)
 * - Client Components / browser code
 * - Any environment where the full engine is unavailable
 *
 * @param raw - The base64url string returned by `toBitmask()`.
 * @returns A `PermissionBitmask` ready to call `.can()`, `.canAll()`, etc.
 *
 * @example
 * ```ts
 * const perms = fromBitmask(cookieValue)
 * if (perms.cannot('billing:manage')) {
 *   return Response.redirect('/403')
 * }
 * ```
 */
export function fromBitmask(raw: string): PermissionBitmask {
  if (!raw) return new PermissionBitmaskImpl([], raw)
  try {
    const decoded = fromBase64Url(raw)
    const perms = decoded ? decoded.split(SEP).filter(Boolean) : []
    return new PermissionBitmaskImpl(perms, raw)
  } catch {
    return new PermissionBitmaskImpl([], raw)
  }
}
