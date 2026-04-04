/**
 * Clerk integration for Permzplus.
 *
 * Provides helpers to embed a permission bitmask into Clerk's
 * `publicMetadata` and to extract it from Clerk session claims on the Edge —
 * with zero database calls after the initial bitmask is computed.
 *
 * **How it works:**
 * 1. When a user's role changes (or at first login), call `computeClerkMetadata()`
 *    and push the result to Clerk via the Backend SDK.
 * 2. Clerk embeds `publicMetadata` in every session JWT it issues.
 * 3. In `middleware.ts`, use `clerkBitmaskGuard()` to extract the bitmask from
 *    the session claims and check permissions before the page renders.
 * 4. In Server Components, read `auth().sessionClaims` and pass the bitmask to
 *    `decodeJWTBitmask()` or `fromBitmask()` for local checks.
 *
 * **No `@clerk/nextjs` import required.** All helpers are typed against plain
 * `Record` shapes compatible with Clerk's types; your own code imports the
 * Clerk SDK and passes its outputs here.
 *
 * @example Sync bitmask at role assignment
 * ```ts
 * import { clerkClient } from '@clerk/nextjs/server'
 * import { computeClerkMetadata } from 'permzplus/adapters/clerk'
 * import { policy } from '@/lib/policy'
 *
 * // Call this whenever you change a user's role
 * async function assignUserRole(userId: string, role: string) {
 *   await policy.assignRole(userId, role)  // your adapter
 *   await clerkClient.users.updateUser(userId, {
 *     publicMetadata: computeClerkMetadata(policy, role),
 *   })
 * }
 * ```
 *
 * @example Edge middleware
 * ```ts
 * // middleware.ts
 * import { clerkMiddleware, getAuth } from '@clerk/nextjs/server'
 * import { clerkBitmaskGuard } from 'permzplus/adapters/clerk'
 *
 * const guard = clerkBitmaskGuard([
 *   { pattern: '/dashboard', permission: 'dashboard:view' },
 *   { pattern: /^\/admin/,  permission: 'admin:access', redirectTo: '/403' },
 * ], { loginUrl: '/sign-in' })
 *
 * export default clerkMiddleware((auth, req) => {
 *   return guard(auth().sessionClaims, req) ?? NextResponse.next()
 * })
 * ```
 *
 * @example Server Component
 * ```tsx
 * import { auth } from '@clerk/nextjs/server'
 * import { fromClerkClaims } from 'permzplus/adapters/clerk'
 *
 * export default async function DashboardPage() {
 *   const { sessionClaims } = auth()
 *   const perms = fromClerkClaims(sessionClaims)
 *   if (perms.cannot('reports:view')) redirect('/403')
 *   // ...
 * }
 * ```
 */

import type { IPolicyEngine } from '../types'
import { toBitmask, fromBitmask, type PermissionBitmask } from '../bitmask'
import type { RouteRule } from '../nextjs-middleware'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * The shape stored in Clerk's `publicMetadata` (or `sessionClaims.public_metadata`
 * in the raw JWT). Merge this with your existing metadata when calling
 * `clerkClient.users.updateUser()`.
 */
export interface PermzClerkMetadata {
  permz: {
    /** Compact base64url permission bitmask. */
    b: string
    /** Unix timestamp (seconds) when this bitmask was computed. */
    iat: number
  }
}

/**
 * The shape of Clerk's session claims as seen by `auth()` or `getAuth()`.
 * Typed minimally so you don't need to import `@clerk/types`.
 */
export interface ClerkSessionClaims {
  /** Embedded from the Clerk User's `publicMetadata`. */
  publicMetadata?: {
    permz?: { b?: string; iat?: number }
    [key: string]: unknown
  }
  /** Raw JWT claim key (snake_case). Present in the raw decoded JWT. */
  public_metadata?: {
    permz?: { b?: string; iat?: number }
    [key: string]: unknown
  }
  [key: string]: unknown
}

/** Options for `clerkBitmaskGuard`. */
export interface ClerkBitmaskGuardOptions {
  /** Redirect unauthenticated requests (no bitmask found). */
  loginUrl?: string
  /** Global redirect for unauthorised requests. Overridden per-rule by `redirectTo`. */
  forbiddenUrl?: string
}

// ---------------------------------------------------------------------------
// computeClerkMetadata — server-side, called when role changes
// ---------------------------------------------------------------------------

/**
 * Computes the permission bitmask for the given role(s) and returns a
 * `PermzClerkMetadata` object ready to merge into a Clerk user's
 * `publicMetadata`.
 *
 * Call this whenever a user's role changes and pass the result to
 * `clerkClient.users.updateUser(userId, { publicMetadata: result })`.
 * Clerk will embed it in every subsequent session JWT automatically.
 *
 * @param engine - The `PolicyEngine` to evaluate permissions against.
 * @param role   - The user's new role or roles.
 * @returns A metadata patch: `{ permz: { b: '...', iat: 1714000000 } }`.
 *
 * @example
 * ```ts
 * await clerkClient.users.updateUser(userId, {
 *   publicMetadata: computeClerkMetadata(policy, 'EDITOR'),
 * })
 * ```
 */
export function computeClerkMetadata(
  engine: IPolicyEngine,
  role: string | string[],
): PermzClerkMetadata {
  return {
    permz: {
      b: toBitmask(engine, role),
      iat: Math.floor(Date.now() / 1000),
    },
  }
}

// ---------------------------------------------------------------------------
// extractFromClerkClaims — read bitmask from session claims
// ---------------------------------------------------------------------------

/**
 * Extracts the raw bitmask string from Clerk's `sessionClaims` object.
 *
 * Checks both `publicMetadata.permz.b` (SDK-decoded form) and
 * `public_metadata.permz.b` (raw JWT claim form).
 *
 * Returns `null` if no bitmask is found — this means `computeClerkMetadata`
 * has not been called yet for this user.
 *
 * @param claims - Clerk's `sessionClaims` object (from `auth().sessionClaims`).
 * @returns The raw base64url bitmask string, or `null`.
 *
 * @example
 * ```ts
 * const raw = extractFromClerkClaims(auth().sessionClaims)
 * if (raw) {
 *   const perms = fromBitmask(raw)
 *   console.log(perms.can('reports:view'))
 * }
 * ```
 */
export function extractFromClerkClaims(claims: ClerkSessionClaims | null | undefined): string | null {
  if (!claims) return null
  return (
    (claims.publicMetadata?.permz?.b ?? null) ??
    (claims.public_metadata?.permz?.b ?? null)
  )
}

// ---------------------------------------------------------------------------
// fromClerkClaims — extract + decode in one call
// ---------------------------------------------------------------------------

/**
 * Extracts and decodes the bitmask from Clerk's `sessionClaims`, returning a
 * `PermissionBitmask` ready for `.can()` checks.
 *
 * Returns an empty bitmask (all checks `false`) when no claim is found,
 * so it is safe to call without guarding.
 *
 * @param claims - Clerk's `sessionClaims` object.
 * @returns A `PermissionBitmask` for local permission checks.
 *
 * @example
 * ```tsx
 * // Server Component
 * const perms = fromClerkClaims(auth().sessionClaims)
 * if (perms.cannot('billing:manage')) redirect('/upgrade')
 * ```
 */
export function fromClerkClaims(claims: ClerkSessionClaims | null | undefined): PermissionBitmask {
  return fromBitmask(extractFromClerkClaims(claims) ?? '')
}

// ---------------------------------------------------------------------------
// clerkBitmaskGuard — Edge-compatible route guard
// ---------------------------------------------------------------------------

/**
 * Creates an Edge-compatible permission guard that reads Clerk session claims
 * and checks permissions before the page renders — zero database calls.
 *
 * Call this **inside** `clerkMiddleware()` where `auth().sessionClaims` is
 * already available and the Clerk JWT has been verified.
 *
 * @param rules   - Route rules (pattern → required permission).
 * @param options - Redirect URLs for unauthenticated / unauthorised requests.
 * @returns A function `(claims, req) => Response | null`.
 *
 * @example
 * ```ts
 * // middleware.ts
 * import { clerkMiddleware } from '@clerk/nextjs/server'
 * import { clerkBitmaskGuard } from 'permzplus/adapters/clerk'
 *
 * const guard = clerkBitmaskGuard([
 *   { pattern: '/dashboard', permission: 'dashboard:view', redirectTo: '/sign-in' },
 *   { pattern: /^\/admin/,  permission: 'admin:access',   redirectTo: '/403' },
 * ])
 *
 * export default clerkMiddleware((auth, req) => {
 *   return guard(auth().sessionClaims, req) ?? NextResponse.next()
 * })
 * ```
 */
export function clerkBitmaskGuard(
  rules: RouteRule[],
  options: ClerkBitmaskGuardOptions = {},
): (claims: ClerkSessionClaims | null | undefined, req: Request) => Response | null {
  return function (
    claims: ClerkSessionClaims | null | undefined,
    req: Request,
  ): Response | null {
    const url = req.url
    const pathname = (() => { try { return new URL(url).pathname } catch { return url } })()

    let matchedRule: RouteRule | null = null
    for (const rule of rules) {
      const p = rule.pattern
      const hit = p instanceof RegExp
        ? p.test(pathname)
        : p.endsWith('*') ? pathname.startsWith(p.slice(0, -1)) : pathname === p
      if (hit) { matchedRule = rule; break }
    }
    if (!matchedRule) return null

    const raw = extractFromClerkClaims(claims)
    if (!raw) {
      return blockResponse(options.loginUrl, url, 401, 'Unauthorized')
    }

    const perms = fromBitmask(raw)
    if (perms.can(matchedRule.permission)) return null

    const dest = matchedRule.redirectTo ?? options.forbiddenUrl
    return blockResponse(dest, url, 403, 'Forbidden')
  }
}

/** @internal */
function blockResponse(dest: string | undefined, base: string, status: number, body: string): Response {
  if (dest) {
    const abs = dest.startsWith('http') ? dest : new URL(dest, base).toString()
    return Response.redirect(abs, 302)
  }
  return new Response(JSON.stringify({ error: body }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}
