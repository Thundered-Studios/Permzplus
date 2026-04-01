import type { IPolicyEngine } from '../types'
import { PermissionDeniedError } from '../errors'

/**
 * Creates a Fastify preHandler hook that enforces a single permission.
 *
 * Extracts the role from the request using `getRoleFromReq` (if provided) or
 * falls back to `request.user?.role`.
 *
 * - Sends `401` if no role can be determined.
 * - Sends `403` if the role lacks the required permission.
 * - Calls `reply.send()` to short-circuit the request; does not call `done`.
 *
 * @example
 * ```ts
 * import Fastify from 'fastify'
 * import { PolicyEngine } from 'permzplus'
 * import { fastifyGuard } from 'permzplus/adapters/fastify'
 *
 * const policy = new PolicyEngine({ roles: [...] })
 * const app = Fastify()
 *
 * app.delete('/posts/:id', {
 *   preHandler: fastifyGuard(policy, 'posts:delete'),
 * }, handler)
 * ```
 */
export function fastifyGuard(
  engine: IPolicyEngine,
  permission: string,
  getRoleFromReq?: (request: unknown) => string | undefined,
): (request: unknown, reply: unknown) => Promise<void> {
  return async function (request: unknown, reply: unknown): Promise<void> {
    const role = getRoleFromReq ? getRoleFromReq(request) : (request as any)?.user?.role

    if (!role) {
      await (reply as any).code(401).send({ error: 'Unauthorized' })
      return
    }

    try {
      engine.assert(role, permission)
    } catch (err) {
      if (err instanceof PermissionDeniedError) {
        await (reply as any).code(403).send({ error: 'Forbidden' })
        return
      }
      throw err
    }
  }
}

/**
 * Creates a Fastify preHandler hook that enforces ALL of the given permissions.
 * The role must have every permission in the array.
 *
 * @example
 * ```ts
 * app.post('/reports', {
 *   preHandler: fastifyGuardAll(policy, ['reports:read', 'reports:export']),
 * }, handler)
 * ```
 */
export function fastifyGuardAll(
  engine: IPolicyEngine,
  permissions: string[],
  getRoleFromReq?: (request: unknown) => string | undefined,
): (request: unknown, reply: unknown) => Promise<void> {
  return async function (request: unknown, reply: unknown): Promise<void> {
    const role = getRoleFromReq ? getRoleFromReq(request) : (request as any)?.user?.role

    if (!role) {
      await (reply as any).code(401).send({ error: 'Unauthorized' })
      return
    }

    try {
      engine.assertAll(role, permissions)
    } catch (err) {
      if (err instanceof PermissionDeniedError) {
        await (reply as any).code(403).send({ error: 'Forbidden' })
        return
      }
      throw err
    }
  }
}

/**
 * Creates a Fastify preHandler hook that enforces AT LEAST ONE of the given
 * permissions (OR logic).
 *
 * @example
 * ```ts
 * app.get('/admin', {
 *   preHandler: fastifyGuardAny(policy, ['admin:read', 'admin:write']),
 * }, handler)
 * ```
 */
export function fastifyGuardAny(
  engine: IPolicyEngine,
  permissions: string[],
  getRoleFromReq?: (request: unknown) => string | undefined,
): (request: unknown, reply: unknown) => Promise<void> {
  return async function (request: unknown, reply: unknown): Promise<void> {
    const role = getRoleFromReq ? getRoleFromReq(request) : (request as any)?.user?.role

    if (!role) {
      await (reply as any).code(401).send({ error: 'Unauthorized' })
      return
    }

    try {
      engine.assertAny(role, permissions)
    } catch (err) {
      if (err instanceof PermissionDeniedError) {
        await (reply as any).code(403).send({ error: 'Forbidden' })
        return
      }
      throw err
    }
  }
}
