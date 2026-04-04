/**
 * Next.js middleware helper for Permzplus.
 *
 * Provides a `createPermissionMiddleware()` factory that decodes a bitmask
 * cookie (set at login by `toBitmask()`) and blocks routes before the page
 * render pipeline even starts — purely in the Edge Runtime, zero DB calls.
 *
 * Import from `permzplus/nextjs/middleware` in your `middleware.ts` file.
 *
 * @example
 * ```ts
 * // middleware.ts
 * import { NextRequest, NextResponse } from 'next/server'
 * import { createPermissionMiddleware } from 'permzplus/nextjs/middleware'
 *
 * const guard = createPermissionMiddleware(
 *   [
 *     { pattern: '/dashboard',   permission: 'dashboard:view' },
 *     { pattern: /^\/admin/,     permission: 'admin:access',   redirectTo: '/403' },
 *     { pattern: '/billing',     permission: 'billing:manage', redirectTo: '/upgrade' },
 *   ],
 *   {
 *     cookieName: 'permz',      // default
 *     loginUrl:   '/login',
 *   }
 * )
 *
 * export function middleware(req: NextRequest) {
 *   const result = guard(req)
 *   if (result) return result          // blocked — redirect or 401/403
 *   return NextResponse.next()         // allowed — continue to page
 * }
 *
 * export const config = {
 *   matcher: ['/dashboard/:path*', '/admin/:path*', '/billing/:path*'],
 * }
 * ```
 */

import { fromBitmask } from './bitmask'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * A route rule that maps a URL pattern to a required permission.
 */
export interface RouteRule {
  /**
   * Pathname to protect. Supports:
   * - Exact string: `'/dashboard'` — matches that exact path
   * - Prefix string ending with `'*'`: `'/admin*'` — matches `/admin` and anything under it
   * - `RegExp`: full regex match against `req.nextUrl.pathname` or `new URL(req.url).pathname`
   */
  pattern: string | RegExp
  /**
   * The Permzplus permission required to access matching routes
   * (e.g. `'dashboard:view'`, `'admin:access'`).
   */
  permission: string
  /**
   * URL to redirect to when the user lacks the required permission.
   * Overrides `options.forbiddenUrl` for this specific rule.
   * When omitted, returns a plain `403 Forbidden` response.
   */
  redirectTo?: string
}

/**
 * Configuration options for `createPermissionMiddleware()`.
 */
export interface PermzMiddlewareOptions {
  /**
   * Name of the cookie that holds the base64url bitmask.
   * Set this cookie at login with `toBitmask(engine, role)`.
   * @default 'permz'
   */
  cookieName?: string
  /**
   * HTTP header name to look for a bitmask (checked after the cookie).
   * Useful for API routes or programmatic clients that pass the bitmask
   * as a bearer-style header.
   * @default 'x-permz-bitmask'
   */
  headerName?: string
  /**
   * URL to redirect unauthenticated requests to (no bitmask found).
   * When omitted, returns a `401 Unauthorized` JSON response.
   *
   * @example '/login'
   */
  loginUrl?: string
  /**
   * Global redirect URL for requests that have a bitmask but lack the
   * required permission. Overridden per-rule by `RouteRule.redirectTo`.
   * When omitted, returns a `403 Forbidden` JSON response.
   *
   * @example '/403'
   */
  forbiddenUrl?: string
  /**
   * Custom extractor function. Return the raw bitmask string or
   * `null`/`undefined` when not present.
   *
   * Overrides the default cookie + header lookup when provided.
   *
   * @example
   * ```ts
   * getBitmask: (req) => req.headers.get('authorization')?.replace('Bearer ', '')
   * ```
   */
  getBitmask?: (req: Request) => string | null | undefined
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function extractBitmask(req: Request, opts: PermzMiddlewareOptions): string | null {
  if (opts.getBitmask) {
    return opts.getBitmask(req) ?? null
  }

  const cookieName = opts.cookieName ?? 'permz'
  const headerName = opts.headerName ?? 'x-permz-bitmask'

  // Cookie lookup — works with the Next.js Request / standard Request APIs
  const cookieHeader = (req as any).cookies?.get?.(cookieName)?.value
    ?? req.headers.get('cookie')
      ?.split(';')
      .map((c: string) => c.trim())
      .find((c: string) => c.startsWith(`${cookieName}=`))
      ?.slice(cookieName.length + 1)
    ?? null

  if (cookieHeader) return cookieHeader

  // Header fallback
  return req.headers.get(headerName)
}

function matchesRoute(pathname: string, pattern: string | RegExp): boolean {
  if (pattern instanceof RegExp) return pattern.test(pathname)
  if (pattern.endsWith('*')) return pathname.startsWith(pattern.slice(0, -1))
  return pathname === pattern
}

function redirectResponse(url: string, base: string): Response {
  const absolute = url.startsWith('http') ? url : new URL(url, base).toString()
  return Response.redirect(absolute, 302)
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Creates a Next.js-compatible middleware guard that enforces per-route
 * permissions using a bitmask cookie — before any page rendering begins.
 *
 * The returned function accepts a standard `Request` (the `NextRequest` that
 * Next.js passes to your `middleware()` export satisfies this) and returns:
 * - `null` — the request is allowed; call `NextResponse.next()`.
 * - A `Response` — the request is blocked; return it directly from `middleware()`.
 *
 * **No database calls. No engine import. Edge-runtime safe.**
 *
 * @param rules   - Ordered list of route rules. Evaluated top-to-bottom; first match wins.
 * @param options - Cookie/header names and fallback redirect URLs.
 * @returns A guard function `(req: Request) => Response | null`.
 *
 * @example
 * ```ts
 * // middleware.ts
 * import { NextRequest, NextResponse } from 'next/server'
 * import { createPermissionMiddleware } from 'permzplus/nextjs/middleware'
 *
 * const guard = createPermissionMiddleware([
 *   { pattern: '/dashboard',  permission: 'dashboard:view', redirectTo: '/login' },
 *   { pattern: /^\/admin/,   permission: 'admin:access',   redirectTo: '/403' },
 * ])
 *
 * export function middleware(req: NextRequest) {
 *   return guard(req) ?? NextResponse.next()
 * }
 * ```
 */
export function createPermissionMiddleware(
  rules: RouteRule[],
  options: PermzMiddlewareOptions = {},
): (req: Request) => Response | null {
  return function (req: Request): Response | null {
    const url = req.url
    const pathname = (() => {
      try {
        return new URL(url).pathname
      } catch {
        return url
      }
    })()

    // Find first matching rule
    let matchedRule: RouteRule | null = null
    for (const rule of rules) {
      if (matchesRoute(pathname, rule.pattern)) {
        matchedRule = rule
        break
      }
    }

    // No rule matches — allow through
    if (!matchedRule) return null

    // Extract bitmask from cookie / header / custom extractor
    const raw = extractBitmask(req, options)

    if (!raw) {
      // No bitmask — unauthenticated
      const loginUrl = options.loginUrl
      if (loginUrl) return redirectResponse(loginUrl, url)
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      })
    }

    // Decode and check permission
    const perms = fromBitmask(raw)
    if (perms.can(matchedRule.permission)) return null

    // Forbidden
    const dest = matchedRule.redirectTo ?? options.forbiddenUrl
    if (dest) return redirectResponse(dest, url)
    return new Response(JSON.stringify({ error: 'Forbidden' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' },
    })
  }
}
