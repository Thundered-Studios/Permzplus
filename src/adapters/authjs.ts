/**
 * Auth.js (NextAuth v4/v5) bridge for Permzplus.
 *
 * Provides a `permzCallbacks()` factory that wires a `PolicyEngine` into
 * Auth.js `jwt` and `session` callbacks, automatically embedding the
 * permission bitmask in the JWT and making a `PermissionBitmask` available
 * on the server-side session object.
 *
 * **How it works:**
 * - `jwt()` callback: computes `toBitmask(engine, user.role)` on first sign-in
 *   and on every role change; stores the result as `token.permz.b`.
 * - `session()` callback: decodes `token.permz.b` into a `PermissionBitmask`
 *   and attaches it to `session.user.permissions`. The raw bitmask string
 *   is also exposed as `session.user.permzBitmask` for Client Components.
 *
 * **Client-side usage:** pass `session.user.permzBitmask` (the plain string) to
 * `<PermissionBitmaskProvider>` or `usePermissions()`. The `PermissionBitmask`
 * instance on `session.user.permissions` is server-only (it won't survive
 * JSON serialisation to the browser).
 *
 * @example Setup (`auth.ts`)
 * ```ts
 * import NextAuth from 'next-auth'
 * import GitHub from 'next-auth/providers/github'
 * import { permzCallbacks } from 'permzplus/adapters/authjs'
 * import { policy } from '@/lib/policy'
 *
 * export const { handlers, auth, signIn, signOut } = NextAuth({
 *   providers: [GitHub],
 *   ...permzCallbacks(policy, {
 *     // Return role(s) from whatever your DB attaches to `user`
 *     getRole: (user) => (user as any).role ?? 'GUEST',
 *   }),
 * })
 * ```
 *
 * @example Server Component
 * ```tsx
 * import { auth } from '@/auth'
 *
 * export default async function DashboardPage() {
 *   const session = await auth()
 *   if (!session?.user.permissions.can('dashboard:view')) redirect('/403')
 *   // ...
 * }
 * ```
 *
 * @example Client Component
 * ```tsx
 * 'use client'
 * import { useSession } from 'next-auth/react'
 * import { usePermissions } from 'permzplus/nextjs/client'
 *
 * export function DeleteButton() {
 *   const { data: session } = useSession()
 *   const perms = usePermissions(session?.user?.permzBitmask ?? '')
 *   if (perms.cannot('posts:delete')) return null
 *   return <button>Delete</button>
 * }
 * ```
 *
 * @example Type augmentation (`auth.d.ts` or `types/next-auth.d.ts`)
 * ```ts
 * import type { PermzSessionUser, PermzToken } from 'permzplus/adapters/authjs'
 *
 * declare module 'next-auth' {
 *   interface Session {
 *     user: PermzSessionUser
 *   }
 * }
 * declare module 'next-auth/jwt' {
 *   interface JWT extends PermzToken {}
 * }
 * ```
 */

import type { IPolicyEngine } from '../types'
import { toBitmask, fromBitmask, type PermissionBitmask } from '../bitmask'

// ---------------------------------------------------------------------------
// Token / session type extensions
// ---------------------------------------------------------------------------

/**
 * Mixin for Auth.js `JWT` — extend your JWT interface with this to get
 * type-safe access to the permzplus bitmask and role stored in the token.
 *
 * @example
 * ```ts
 * // types/next-auth.d.ts
 * import type { PermzToken } from 'permzplus/adapters/authjs'
 * declare module 'next-auth/jwt' {
 *   interface JWT extends PermzToken {}
 * }
 * ```
 */
export interface PermzToken {
  /** The permzplus bitmask claim — embedded by `permzCallbacks`. */
  permz?: {
    /** Compact base64url permission bitmask. */
    b: string
    /** Unix timestamp (seconds) when this bitmask was computed. */
    iat: number
  }
  /**
   * The user's role(s) — stored alongside the bitmask so the bitmask can be
   * refreshed when the role changes (e.g. after an admin role upgrade).
   */
  role?: string | string[]
}

/**
 * The shape added to `session.user` by `permzCallbacks`.
 *
 * Extend `next-auth`'s `Session['user']` with this type:
 *
 * ```ts
 * declare module 'next-auth' {
 *   interface Session {
 *     user: PermzSessionUser
 *   }
 * }
 * ```
 */
export interface PermzSessionUser {
  name?: string | null
  email?: string | null
  image?: string | null
  /** The user's role(s) as stored in the JWT. */
  role?: string | string[]
  /**
   * Decoded `PermissionBitmask` — available server-side via `auth()`.
   * **Not serialisable:** this instance is re-created on every `auth()` call
   * and should NOT be sent to the client. Use `permzBitmask` for Client Components.
   */
  permissions: PermissionBitmask
  /**
   * Raw base64url bitmask string — safe to pass to the client.
   * Pass to `<PermissionBitmaskProvider bitmask={session.user.permzBitmask}>` or
   * `usePermissions(session.user.permzBitmask)`.
   */
  permzBitmask?: string
}

// ---------------------------------------------------------------------------
// permzCallbacks options
// ---------------------------------------------------------------------------

/**
 * Configuration for `permzCallbacks()`.
 */
export interface PermzCallbacksOptions<TUser = Record<string, unknown>> {
  /**
   * Extract the role (or roles) from the Auth.js `user` object.
   * Called during the `jwt()` callback on first sign-in.
   *
   * Return `null` or `undefined` to skip bitmask computation for this user
   * (e.g. unverified accounts).
   *
   * @example
   * ```ts
   * getRole: (user) => user.role as string
   * // or multi-role:
   * getRole: (user) => (user.roles as string[]) ?? []
   * ```
   */
  getRole: (user: TUser) => string | string[] | null | undefined

  /**
   * Optional: detect whether the role has changed since the token was issued,
   * triggering a bitmask refresh mid-session.
   *
   * Called on every JWT rotation. When it returns `true`, `toBitmask()` is
   * called again and `token.permz` is updated. Use this to avoid stale
   * permissions after an admin promotes/demotes a user.
   *
   * @example
   * ```ts
   * isRoleStale: async (token) => {
   *   const latestRole = await db.users.findOne(token.sub).role
   *   return latestRole !== token.role
   * }
   * ```
   */
  isRoleStale?: (token: PermzToken & Record<string, unknown>) => boolean | Promise<boolean>
}

// ---------------------------------------------------------------------------
// permzCallbacks — the main factory
// ---------------------------------------------------------------------------

/**
 * Returns an Auth.js configuration fragment with `callbacks.jwt` and
 * `callbacks.session` pre-wired to embed and decode the permission bitmask.
 *
 * Spread the return value into your `NextAuth({})` config:
 *
 * ```ts
 * export const { handlers, auth } = NextAuth({
 *   providers: [...],
 *   ...permzCallbacks(policy, { getRole: (user) => user.role }),
 * })
 * ```
 *
 * @param engine  - The `PolicyEngine` to compute bitmasks against.
 * @param options - Role extraction and optional staleness check.
 */
export function permzCallbacks<TUser = Record<string, unknown>>(
  engine: IPolicyEngine,
  options: PermzCallbacksOptions<TUser>,
): {
  callbacks: {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    jwt: (params: any) => Promise<any>
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    session: (params: any) => any
  }
} {
  return {
    callbacks: {
      async jwt({ token, user, trigger }: {
        token: PermzToken & Record<string, unknown>
        user?: TUser
        trigger?: string
      }) {
        // First sign-in: user is populated, extract role and compute bitmask
        if (user) {
          const role = options.getRole(user)
          if (role) {
            token.role = role
            token.permz = {
              b: toBitmask(engine, role),
              iat: Math.floor(Date.now() / 1000),
            }
          }
          return token
        }

        // Session update (trigger === 'update') or rotation: check for stale role
        if (token.role && options.isRoleStale) {
          const stale = await options.isRoleStale(token)
          if (stale) {
            token.permz = {
              b: toBitmask(engine, token.role),
              iat: Math.floor(Date.now() / 1000),
            }
          }
        }

        return token
      },

      session({ session, token }: {
        session: Record<string, unknown> & { user?: Record<string, unknown> }
        token: PermzToken & Record<string, unknown>
      }) {
        const bitmask = token.permz?.b
        return {
          ...session,
          user: {
            ...(session.user ?? {}),
            role: token.role,
            permzBitmask: bitmask,
            // Decoded instance — server-side only, re-created each auth() call
            permissions: fromBitmask(bitmask ?? ''),
          } satisfies PermzSessionUser,
        }
      },
    },
  }
}

// ---------------------------------------------------------------------------
// Standalone helpers
// ---------------------------------------------------------------------------

/**
 * Decodes a raw bitmask string into a `PermissionBitmask`.
 * A convenience wrapper around `fromBitmask` with an Auth.js-idiomatic name.
 *
 * @example
 * ```ts
 * // Inside an API route or Server Action
 * const session = await auth()
 * const perms = withPermissions(session.user.permzBitmask)
 * perms.can('posts:publish')
 * ```
 */
export function withPermissions(bitmask: string | undefined | null): PermissionBitmask {
  return fromBitmask(bitmask ?? '')
}
