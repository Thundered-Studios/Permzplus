import type { IPolicyEngine } from '../types'
import { PermissionDeniedError } from '../errors'

/**
 * Creates a tRPC middleware that enforces a single permission.
 * Expects `ctx.role` or `ctx.user.role` on the tRPC context.
 *
 * Compatible with tRPC v11 (uses the `middleware` factory pattern — caller
 * supplies their own `t.middleware` as the first argument to avoid a peer dep).
 *
 * @example
 * const t = initTRPC.context<{ user: { role: string } }>().create()
 * const isAllowed = trpcPermission(t.middleware, policy, 'posts:read')
 * export const protectedProcedure = t.procedure.use(isAllowed)
 */
export function trpcPermission(
  middlewareFn: (fn: (opts: { ctx: unknown; next: (opts?: unknown) => unknown }) => unknown) => unknown,
  engine: IPolicyEngine,
  permission: string,
): unknown {
  return middlewareFn(({ ctx, next }: { ctx: unknown; next: (opts?: unknown) => unknown }) => {
    const context = ctx as Record<string, unknown>
    const role = (context?.role ?? (context?.user as Record<string, unknown>)?.role) as string | undefined
    if (!role) throw new PermissionDeniedError('anonymous', permission)
    engine.assert(role, permission)
    return next()
  })
}

/**
 * Like `trpcPermission` but the role must have ALL of the given permissions.
 */
export function trpcPermissions(
  middlewareFn: (fn: (opts: { ctx: unknown; next: (opts?: unknown) => unknown }) => unknown) => unknown,
  engine: IPolicyEngine,
  permissions: string[],
): unknown {
  return middlewareFn(({ ctx, next }: { ctx: unknown; next: (opts?: unknown) => unknown }) => {
    const context = ctx as Record<string, unknown>
    const role = (context?.role ?? (context?.user as Record<string, unknown>)?.role) as string | undefined
    if (!role) throw new PermissionDeniedError('anonymous', permissions.join(' & '))
    engine.assertAll(role, permissions)
    return next()
  })
}

/**
 * Returns a tRPC-compatible guard that calls `safeCan` — returns false instead
 * of throwing for unknown roles, useful for conditional UI queries.
 */
export function trpcCanCheck(
  engine: IPolicyEngine,
  permission: string,
): (ctx: unknown) => boolean {
  return function (ctx: unknown) {
    const context = ctx as Record<string, unknown>
    const role = (context?.role ?? (context?.user as Record<string, unknown>)?.role) as string | undefined
    if (!role) return false
    return engine.safeCan(role, permission)
  }
}
