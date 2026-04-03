import type { IPolicyEngine } from '../types'
import { PermissionDeniedError } from '../errors'

/**
 * Wraps a GraphQL resolver to enforce a permission check before execution.
 * Extracts `role` from `context.role` or `context.user?.role`.
 *
 * @example
 * const resolvers = {
 *   Query: {
 *     posts: withPermission(policy, 'posts:read', () => db.posts.findAll()),
 *   }
 * }
 */
export function withPermission<TParent = unknown, TArgs = unknown, TContext = unknown, TReturn = unknown>(
  engine: IPolicyEngine,
  permission: string,
  resolver: (parent: TParent, args: TArgs, context: TContext, info: unknown) => TReturn,
): (parent: TParent, args: TArgs, context: TContext, info: unknown) => TReturn {
  return function (parent, args, context, info) {
    const ctx = context as Record<string, unknown>
    const role = (ctx?.role ?? (ctx?.user as Record<string, unknown>)?.role) as string | undefined
    if (!role) throw new PermissionDeniedError('anonymous', permission)
    engine.assert(role, permission)
    return resolver(parent, args, context, info)
  }
}

/**
 * Like `withPermission` but the role must have ALL of the given permissions.
 */
export function withPermissions<TParent = unknown, TArgs = unknown, TContext = unknown, TReturn = unknown>(
  engine: IPolicyEngine,
  permissions: string[],
  resolver: (parent: TParent, args: TArgs, context: TContext, info: unknown) => TReturn,
): (parent: TParent, args: TArgs, context: TContext, info: unknown) => TReturn {
  return function (parent, args, context, info) {
    const ctx = context as Record<string, unknown>
    const role = (ctx?.role ?? (ctx?.user as Record<string, unknown>)?.role) as string | undefined
    if (!role) throw new PermissionDeniedError('anonymous', permissions.join(' & '))
    engine.assertAll(role, permissions)
    return resolver(parent, args, context, info)
  }
}

/**
 * Creates a permission-checking middleware compatible with graphql-shield and
 * other schema-directive patterns. Returns `true` or `false`.
 *
 * @example
 * const isAllowed = createPermissionRule(policy, 'posts:read')
 * // use with graphql-shield: rule()(isAllowed)
 */
export function createPermissionRule(
  engine: IPolicyEngine,
  permission: string,
): (parent: unknown, args: unknown, context: unknown) => boolean {
  return function (_parent, _args, context) {
    const ctx = context as Record<string, unknown>
    const role = (ctx?.role ?? (ctx?.user as Record<string, unknown>)?.role) as string | undefined
    if (!role) return false
    return engine.safeCan(role, permission)
  }
}
