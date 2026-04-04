/**
 * Next.js App Router — Server-side utilities for Permzplus.
 *
 * Import from `permzplus/nextjs` in Server Components, Server Actions, and
 * `layout.tsx` files. All exports in this file are RSC-safe: no React hooks,
 * no `'use client'` boundary, no client-only APIs.
 *
 * For client-side hooks and components, use `permzplus/nextjs/client`.
 * For middleware helpers, use `permzplus/nextjs/middleware`.
 *
 * @example Server Component
 * ```tsx
 * // app/dashboard/page.tsx  (Server Component — no 'use client')
 * import { CanServer, getPermissionMap } from 'permzplus/nextjs'
 * import { policy } from '@/lib/policy'
 * import { getSession } from '@/lib/auth'
 *
 * export default async function DashboardPage() {
 *   const session = await getSession()
 *   const permMap = getPermissionMap(policy, session.role)
 *
 *   return (
 *     <>
 *       <CanServer permission="reports:view" engine={policy} role={session.role}>
 *         <ReportsDashboard />
 *       </CanServer>
 *
 *       // Pass bitmask down to Client Components so they can check locally
 *       <ClientSidebar permMap={permMap} />
 *     </>
 *   )
 * }
 * ```
 *
 * @example Server Action
 * ```ts
 * // app/actions.ts
 * 'use server'
 * import { getPermissionMap } from 'permzplus/nextjs'
 * import { policy } from '@/lib/policy'
 * import { getSession } from '@/lib/auth'
 *
 * export async function fetchPermissionMap() {
 *   const session = await getSession()
 *   return getPermissionMap(policy, session.role)
 * }
 * ```
 */

import type { ReactNode } from 'react'
import type { IPolicyEngine } from './types'
import { toBitmask } from './bitmask'

// ---------------------------------------------------------------------------
// Permission map (serializable, safe to pass as a prop or Server Action return)
// ---------------------------------------------------------------------------

/**
 * A serializable snapshot of a user's permission set.
 *
 * - `bitmask` — compact base64url string. Pass to `usePermissions()` on the
 *   client so the browser can do permission checks locally.
 * - `role` — the role(s) the map was computed for (informational).
 *
 * The object is plain-JSON-serializable: safe as a Server Action return value
 * or as a prop from Server Component to Client Component.
 */
export interface PermissionMap {
  /**
   * Compact base64url string encoding the user's effective permissions.
   * Decode on the client with `usePermissions(permMap.bitmask)` or
   * `fromBitmask(permMap.bitmask)`.
   */
  bitmask: string
  /** The role(s) this map was computed for. */
  role: string | string[]
}

/**
 * Computes a user's effective permission set and returns a `PermissionMap`
 * that is safe to pass to Client Components or return from a Server Action.
 *
 * Call this once per request (e.g. in a root layout or a Server Action) and
 * pass the result down. The returned object is plain-JSON-serializable.
 *
 * @param engine - The `PolicyEngine` to query.
 * @param role   - The current user's role or roles.
 * @returns A `PermissionMap` with a `bitmask` string for the client.
 *
 * @example
 * ```ts
 * const permMap = getPermissionMap(policy, session.role)
 * // permMap.bitmask → compact base64url string
 * // Pass to: <ClientNav permMap={permMap} />
 * // Or: return permMap  (from a 'use server' action)
 * ```
 */
export function getPermissionMap(engine: IPolicyEngine, role: string | string[]): PermissionMap {
  return {
    bitmask: toBitmask(engine, role),
    role,
  }
}

// ---------------------------------------------------------------------------
// CanServer — RSC-safe permission gate
// ---------------------------------------------------------------------------

export interface CanServerProps {
  /** The permission string to check (e.g. `"posts:delete"`). */
  permission: string
  /** The `PolicyEngine` instance. Typically imported from your policy module. */
  engine: IPolicyEngine
  /** The current user's role or roles. */
  role: string | string[]
  /** Content to render when the check passes. */
  children: ReactNode
  /** Content to render when the check fails. Defaults to `null`. */
  fallback?: ReactNode
}

/**
 * A React Server Component permission gate.
 *
 * The permission check runs synchronously on the server during RSC rendering —
 * zero latency, zero client bundle cost, no data sent to the browser.
 * The `children` subtree (which may include Client Components) is only
 * rendered when the check passes, so it never reaches the client when denied.
 *
 * This component uses **no React hooks** and **no client APIs**, making it
 * safe to use in any Server Component file.
 *
 * @example
 * ```tsx
 * <CanServer permission="billing:manage" engine={policy} role={session.role}>
 *   <BillingPanel />
 * </CanServer>
 * ```
 *
 * @example With fallback
 * ```tsx
 * <CanServer
 *   permission="admin:access"
 *   engine={policy}
 *   role={session.role}
 *   fallback={<p>You do not have access to this section.</p>}
 * >
 *   <AdminDashboard />
 * </CanServer>
 * ```
 */
export function CanServer({
  permission,
  engine,
  role,
  children,
  fallback = null,
}: CanServerProps): ReactNode {
  const roles = Array.isArray(role) ? role : [role]
  const allowed = roles.some((r) => {
    try {
      return engine.safeCan(r, permission)
    } catch {
      return false
    }
  })
  return (allowed ? children : fallback) as ReactNode
}
