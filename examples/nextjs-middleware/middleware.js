/**
 * Permzplus Next.js Middleware Example
 *
 * Place this file at the root of your Next.js project (alongside `app/` or `pages/`).
 * It runs on every matched request before the page renders.
 *
 * Route protection map:
 *   /admin/*        → requires admin:panel   (ADMIN level 80+)
 *   /api/users/*    → requires users:ban     (ADMIN level 80+)
 *   /api/posts/*    → requires posts:write   (USER level 20+)
 *   /dashboard/*    → requires posts:read    (GUEST level 0+)
 *   everything else → public
 *
 * The role is read from the `x-role` request header. In a real app you would
 * verify a JWT or session cookie and set the role server-side — never trust a
 * raw header from the client in production.
 */

import { PolicyEngine } from 'permzplus'
import { nextjsGuard } from 'permzplus/guard'

// ---------------------------------------------------------------------------
// 1. Build the policy engine once at module load time.
//    Built-in roles are loaded automatically. We add one custom role here.
// ---------------------------------------------------------------------------

const policy = new PolicyEngine()

// CONTENT_EDITOR sits between USER (20) and MODERATOR (40).
// It inherits USER permissions and adds posts:publish.
policy.addRole({ name: 'CONTENT_EDITOR', level: 30, permissions: ['posts:publish'] })

// ---------------------------------------------------------------------------
// 2. Pre-build guards for each protected route group.
// ---------------------------------------------------------------------------

const requireAdminPanel  = nextjsGuard(policy, 'admin:panel')
const requireUsersBan    = nextjsGuard(policy, 'users:ban')
const requirePostsWrite  = nextjsGuard(policy, 'posts:write')
const requirePostsRead   = nextjsGuard(policy, 'posts:read')

// Extract role from the x-role header (demo only — use a real auth solution).
function getRoleFromReq(req) {
  return req.headers.get('x-role') ?? undefined
}

// ---------------------------------------------------------------------------
// 3. The middleware function — called by Next.js on every matched request.
// ---------------------------------------------------------------------------

export function middleware(request) {
  const { pathname } = new URL(request.url)
  const role = getRoleFromReq(request)

  // Attach role to a custom header so server components can read it easily.
  const requestHeaders = new Headers(request.headers)
  if (role) {
    requestHeaders.set('x-resolved-role', role)
  }

  // Route-level permission checks
  if (pathname.startsWith('/admin')) {
    const denied = requireAdminPanel(request)
    if (denied) return denied
  } else if (pathname.startsWith('/api/users')) {
    const denied = requireUsersBan(request)
    if (denied) return denied
  } else if (pathname.startsWith('/api/posts')) {
    const denied = requirePostsWrite(request)
    if (denied) return denied
  } else if (pathname.startsWith('/dashboard')) {
    const denied = requirePostsRead(request)
    if (denied) return denied
  }

  // Allow the request through, forwarding the resolved-role header.
  const { NextResponse } = require('next/server')
  return NextResponse.next({ request: { headers: requestHeaders } })
}

// ---------------------------------------------------------------------------
// 4. Matcher — tell Next.js which paths this middleware should run on.
//    Excludes static assets and Next.js internals for performance.
// ---------------------------------------------------------------------------

export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon.ico).*)',
  ],
}
