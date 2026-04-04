/**
 * JWT private-claim helpers for Permzplus.
 *
 * Provides type-safe utilities for embedding permission bitmasks into JWT
 * payloads (Clerk `publicMetadata`, Auth.js tokens, custom JWTs) and for
 * decoding them on the Edge without a database call.
 *
 * **Security model**
 * - Only the *computed bitmask* (`permz.b`) belongs in a JWT — never the raw
 *   permission arrays, role definitions, or ABAC conditions.
 * - `SafeJWTPayload<T>` statically forbids the `engine`, `policy`, and
 *   `permissions` keys, preventing accidental inclusion of server-side state.
 * - The JWT **must** be signed and verified by your auth layer (Clerk / Auth.js /
 *   jose). This module only reads claims; it never verifies signatures.
 *
 * @example Stuff claims at login
 * ```ts
 * import { stuffBitmask } from 'permzplus/jwt'
 * import { policy } from '@/lib/policy'
 *
 * const claims = stuffBitmask(policy, user.role)
 * // → { permz: { b: 'cG9zdHM6cmVhZA', iat: 1714000000 } }
 *
 * // Clerk: merge into publicMetadata
 * await clerkClient.users.updateUser(userId, { publicMetadata: claims })
 *
 * // Auth.js: return from the jwt() callback
 * // jose: spread into your payload before signing
 * ```
 *
 * @example Edge middleware (Vercel / Cloudflare Workers)
 * ```ts
 * import { createJWTMiddlewareGuard } from 'permzplus/jwt'
 *
 * const guard = createJWTMiddlewareGuard([
 *   { pattern: '/dashboard', permission: 'dashboard:view' },
 *   { pattern: /^\/admin/,  permission: 'admin:access', redirectTo: '/403' },
 * ], { loginUrl: '/login' })
 *
 * export default function middleware(req: Request) {
 *   return guard(req) ?? NextResponse.next()
 * }
 * ```
 */

import type { IPolicyEngine } from './types'
import { toBitmask, fromBitmask, type PermissionBitmask } from './bitmask'
import type { RouteRule, PermzMiddlewareOptions } from './nextjs-middleware'

// ---------------------------------------------------------------------------
// Claim key
// ---------------------------------------------------------------------------

/** The JWT claim key used by permzplus. Override via {@link PermzJWTOptions.claimKey}. */
export const PERMZ_CLAIM_KEY = 'permz' as const

// ---------------------------------------------------------------------------
// Type-safe payload types
// ---------------------------------------------------------------------------

/**
 * The shape of the permzplus private claim embedded in a JWT.
 *
 * Use as a mixin with your own token type:
 * ```ts
 * type MyToken = DefaultJWT & PermzClaims
 * ```
 */
export interface PermzClaims {
  [PERMZ_CLAIM_KEY]?: {
    /**
     * Compact base64url permission bitmask.
     * Decode with `fromBitmask(b)` or `decodeJWTBitmask(token)`.
     */
    b: string
    /**
     * Unix timestamp (seconds) when this bitmask was computed.
     * Compare to `user.roleUpdatedAt` to detect stale tokens.
     */
    iat?: number
  }
}

/**
 * A JWT payload type that is statically safe to send to the client.
 *
 * Omits `engine`, `policy`, and `permissions` keys so that TypeScript
 * prevents developers from accidentally serialising server-side state into
 * a JWT or session object.
 *
 * @example
 * ```ts
 * import type { SafeJWTPayload } from 'permzplus/jwt'
 *
 * // Your custom JWT type — server-side fields, bitmask for the client
 * type AppToken = SafeJWTPayload<{
 *   sub: string
 *   role: string
 *   email: string
 * }>
 *
 * // TypeScript error: 'engine' is forbidden in SafeJWTPayload
 * const bad: AppToken = { engine: policyEngine, role: 'ADMIN' }  // ✗
 * const good: AppToken = { role: 'ADMIN', permz: { b: bitmask } } // ✓
 * ```
 */
export type SafeJWTPayload<T extends Record<string, unknown> = Record<string, unknown>> =
  Omit<T, 'engine' | 'policy' | '_policyEngine' | 'permissions'> & PermzClaims

// ---------------------------------------------------------------------------
// stuffBitmask — compute and return claims
// ---------------------------------------------------------------------------

/**
 * Computes a permission bitmask for the given role(s) and returns a
 * `PermzClaims` object ready to merge into a JWT payload or session metadata.
 *
 * Only the *result* of the permission evaluation is included — never the
 * policy rules, conditions, or engine state. Safe to send to the client.
 *
 * @param engine - The `PolicyEngine` to evaluate permissions against.
 * @param role   - The user's role or array of roles.
 * @returns A `PermzClaims` object: `{ permz: { b: '...', iat: 1714000000 } }`.
 *
 * @example
 * ```ts
 * // Clerk
 * const claims = stuffBitmask(policy, user.role)
 * await clerkClient.users.updateUser(userId, { publicMetadata: claims })
 *
 * // Auth.js jwt() callback
 * callbacks: {
 *   jwt({ token, user }) {
 *     if (user?.role) Object.assign(token, stuffBitmask(policy, user.role))
 *     return token
 *   }
 * }
 *
 * // jose
 * const jwt = await new SignJWT({ sub: userId, ...stuffBitmask(policy, role) })
 *   .setProtectedHeader({ alg: 'HS256' })
 *   .sign(secret)
 * ```
 */
export function stuffBitmask(
  engine: IPolicyEngine,
  role: string | string[],
): PermzClaims {
  return {
    [PERMZ_CLAIM_KEY]: {
      b: toBitmask(engine, role),
      iat: Math.floor(Date.now() / 1000),
    },
  }
}

// ---------------------------------------------------------------------------
// extractJWTBitmask — extract the raw string
// ---------------------------------------------------------------------------

/**
 * Extracts the raw bitmask string from either:
 * - A raw JWT string (decoded but **not** verified — use your auth layer for that)
 * - An already-decoded JWT payload object
 *
 * Returns `null` when the claim is absent or the input is malformed.
 * Safe to call with untrusted input — all errors are caught internally.
 *
 * **JWT strings are decoded, not verified.** Signature verification must be
 * handled by your auth layer before you trust the result of `can()`.
 *
 * @param jwtOrPayload - A raw `"header.payload.sig"` JWT string, or a decoded
 *                       payload object (e.g. `auth().sessionClaims` in Clerk).
 * @returns The base64url bitmask string, or `null` if not present.
 *
 * @example
 * ```ts
 * // From Clerk's sessionClaims (already decoded)
 * const raw = extractJWTBitmask(auth().sessionClaims)
 *
 * // From a raw Bearer token
 * const token = req.headers.get('authorization')?.slice(7)
 * const raw = extractJWTBitmask(token)
 * ```
 */
export function extractJWTBitmask(jwtOrPayload: string | Record<string, unknown> | null | undefined): string | null {
  if (!jwtOrPayload) return null
  try {
    if (typeof jwtOrPayload === 'string') {
      const parts = jwtOrPayload.split('.')
      if (parts.length < 2) return null
      const seg = parts[1]
      // base64url → base64 → JSON
      const padded = seg.replace(/-/g, '+').replace(/_/g, '/')
      const rem = padded.length % 4
      const b64 = rem === 0 ? padded : padded + '='.repeat(4 - rem)
      const decoded = JSON.parse(atob(b64)) as Record<string, unknown>
      return (decoded?.[PERMZ_CLAIM_KEY] as any)?.b ?? null
    }
    return (jwtOrPayload?.[PERMZ_CLAIM_KEY] as any)?.b ?? null
  } catch {
    return null
  }
}

// ---------------------------------------------------------------------------
// decodeJWTBitmask — extract + decode in one call
// ---------------------------------------------------------------------------

/**
 * Extracts the bitmask from a JWT and decodes it into a `PermissionBitmask`
 * ready for `.can()` / `.canAll()` / `.canAny()` checks.
 *
 * Returns an empty `PermissionBitmask` (all checks return `false`) when the
 * claim is absent — no throwing, safe to call without guarding.
 *
 * @param jwtOrPayload - Raw JWT string or decoded payload object.
 * @returns A `PermissionBitmask` for local permission checks.
 *
 * @example
 * ```ts
 * const perms = decodeJWTBitmask(req.headers.get('authorization')?.slice(7))
 * if (perms.cannot('reports:view')) return new Response('Forbidden', { status: 403 })
 * ```
 */
export function decodeJWTBitmask(jwtOrPayload: string | Record<string, unknown> | null | undefined): PermissionBitmask {
  const raw = extractJWTBitmask(jwtOrPayload)
  return fromBitmask(raw ?? '')
}

// ---------------------------------------------------------------------------
// createJWTMiddlewareGuard — tiny Edge-compatible route guard
// ---------------------------------------------------------------------------

/** Options for {@link createJWTMiddlewareGuard}. */
export interface JWTMiddlewareOptions extends Pick<PermzMiddlewareOptions, 'loginUrl' | 'forbiddenUrl'> {
  /**
   * Custom function to extract the raw JWT string from the request.
   * Default: checks `Authorization: Bearer <token>` then the `__session` cookie
   * (used by Clerk) then the `permz-token` cookie.
   */
  getJWT?: (req: Request) => string | null | undefined
}

/**
 * Creates a tiny, Edge-compatible route guard that:
 * 1. Extracts a JWT from the `Authorization` header or a session cookie.
 * 2. Decodes (NOT verifies) the `permz.b` claim.
 * 3. Checks the decoded permission against your route rules.
 * 4. Returns `null` (allow) or a `Response` (block/redirect).
 *
 * **No database calls. No adapter. No engine import. ~300 bytes minified.**
 *
 * This is the zero-latency Edge path: the JWT has already been verified by
 * your auth layer (Clerk middleware, Auth.js, etc.) before this function runs.
 *
 * @param rules   - Route rules (same type as `createPermissionMiddleware`).
 * @param options - JWT extraction and redirect configuration.
 * @returns A guard `(req: Request) => Response | null`.
 *
 * @example
 * ```ts
 * // middleware.ts — Clerk app
 * import { clerkMiddleware } from '@clerk/nextjs/server'
 * import { createJWTMiddlewareGuard } from 'permzplus/jwt'
 *
 * const guard = createJWTMiddlewareGuard([
 *   { pattern: '/dashboard',  permission: 'dashboard:view' },
 *   { pattern: /^\/admin/,   permission: 'admin:access', redirectTo: '/403' },
 * ], { loginUrl: '/sign-in' })
 *
 * export default clerkMiddleware((auth, req) => {
 *   return guard(req) ?? NextResponse.next()
 * })
 * ```
 */
export function createJWTMiddlewareGuard(
  rules: RouteRule[],
  options: JWTMiddlewareOptions = {},
): (req: Request) => Response | null {
  return function (req: Request): Response | null {
    const url = req.url
    const pathname = (() => { try { return new URL(url).pathname } catch { return url } })()

    // Find first matching rule
    let matchedRule: RouteRule | null = null
    for (const rule of rules) {
      const p = rule.pattern
      const hit = p instanceof RegExp
        ? p.test(pathname)
        : p.endsWith('*') ? pathname.startsWith(p.slice(0, -1)) : pathname === p
      if (hit) { matchedRule = rule; break }
    }
    if (!matchedRule) return null

    // Extract JWT
    const jwt = options.getJWT
      ? (options.getJWT(req) ?? null)
      : extractJWT(req)

    if (!jwt) {
      return block(options.loginUrl, url, 401, 'Unauthorized')
    }

    const perms = decodeJWTBitmask(jwt)
    if (perms.can(matchedRule.permission)) return null

    const dest = matchedRule.redirectTo ?? options.forbiddenUrl
    return block(dest, url, 403, 'Forbidden')
  }
}

/** @internal */
function extractJWT(req: Request): string | null {
  // 1. Authorization: Bearer <token>
  const auth = req.headers.get('authorization')
  if (auth?.startsWith('Bearer ')) return auth.slice(7)

  // 2. __session cookie (Clerk)
  // 3. permz-token cookie (generic)
  const cookie = req.headers.get('cookie')
  if (cookie) {
    for (const name of ['__session', 'permz-token']) {
      const pair = cookie.split(';').map(s => s.trim()).find(s => s.startsWith(`${name}=`))
      if (pair) return pair.slice(name.length + 1)
    }
  }
  return null
}

/** @internal */
function block(dest: string | undefined, base: string, status: number, body: string): Response {
  if (dest) {
    const abs = dest.startsWith('http') ? dest : new URL(dest, base).toString()
    return Response.redirect(abs, 302)
  }
  return new Response(JSON.stringify({ error: body }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}
