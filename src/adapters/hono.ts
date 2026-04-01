import type { IPolicyEngine } from '../types'
import { PermissionDeniedError } from '../errors'

/**
 * Creates a Hono middleware that enforces a single permission.
 *
 * Extracts the role from the context using `getRoleFromCtx` (if provided) or
 * falls back to `c.get('user')?.role` then `c.req.header('x-role')`.
 *
 * - Returns a `403` JSON response if the role lacks the permission.
 * - Returns a `401` JSON response if no role can be determined.
 * - Calls `next()` to continue the middleware chain on success.
 *
 * @example
 * ```ts
 * import { Hono } from 'hono'
 * import { PolicyEngine } from 'permzplus'
 * import { honoGuard } from 'permzplus/adapters/hono'
 *
 * const policy = new PolicyEngine({ roles: [...] })
 * const app = new Hono()
 *
 * app.delete('/posts/:id', honoGuard(policy, 'posts:delete'), handler)
 * ```
 */
export function honoGuard(
  engine: IPolicyEngine,
  permission: string,
  getRoleFromCtx?: (c: unknown) => string | undefined,
): (c: unknown, next: () => Promise<void>) => Promise<Response | void> {
  return async function (c: unknown, next: () => Promise<void>): Promise<Response | void> {
    const role =
      getRoleFromCtx?.(c) ??
      (c as any).get?.('user')?.role ??
      (c as any).req?.header?.('x-role')

    if (!role) {
      return (c as any).json({ error: 'Unauthorized' }, 401)
    }

    try {
      engine.assert(role, permission)
      return next()
    } catch (err) {
      if (err instanceof PermissionDeniedError) {
        return (c as any).json({ error: 'Forbidden' }, 403)
      }
      throw err
    }
  }
}

/**
 * Creates a Hono middleware that enforces ALL of the given permissions.
 *
 * @example
 * ```ts
 * app.post('/reports', honoGuardAll(policy, ['reports:read', 'reports:export']), handler)
 * ```
 */
export function honoGuardAll(
  engine: IPolicyEngine,
  permissions: string[],
  getRoleFromCtx?: (c: unknown) => string | undefined,
): (c: unknown, next: () => Promise<void>) => Promise<Response | void> {
  return async function (c: unknown, next: () => Promise<void>): Promise<Response | void> {
    const role =
      getRoleFromCtx?.(c) ??
      (c as any).get?.('user')?.role ??
      (c as any).req?.header?.('x-role')

    if (!role) {
      return (c as any).json({ error: 'Unauthorized' }, 401)
    }

    try {
      engine.assertAll(role, permissions)
      return next()
    } catch (err) {
      if (err instanceof PermissionDeniedError) {
        return (c as any).json({ error: 'Forbidden' }, 403)
      }
      throw err
    }
  }
}

/**
 * Creates a Hono middleware that enforces AT LEAST ONE of the given permissions.
 *
 * @example
 * ```ts
 * app.get('/admin', honoGuardAny(policy, ['admin:read', 'admin:write']), handler)
 * ```
 */
export function honoGuardAny(
  engine: IPolicyEngine,
  permissions: string[],
  getRoleFromCtx?: (c: unknown) => string | undefined,
): (c: unknown, next: () => Promise<void>) => Promise<Response | void> {
  return async function (c: unknown, next: () => Promise<void>): Promise<Response | void> {
    const role =
      getRoleFromCtx?.(c) ??
      (c as any).get?.('user')?.role ??
      (c as any).req?.header?.('x-role')

    if (!role) {
      return (c as any).json({ error: 'Unauthorized' }, 401)
    }

    try {
      engine.assertAny(role, permissions)
      return next()
    } catch (err) {
      if (err instanceof PermissionDeniedError) {
        return (c as any).json({ error: 'Forbidden' }, 403)
      }
      throw err
    }
  }
}
