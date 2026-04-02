/**
 * Testing utilities for Permzplus.
 *
 * Import from `permzplus/testing` — these helpers are intentionally excluded
 * from the main bundle so they are never shipped in production builds.
 *
 * @example
 * import { createTestPolicy, expectCan, expectCannot } from 'permzplus/testing'
 */

import type { RoleDefinition, PolicyOptions } from './types'
import { PolicyEngine } from './policy'
import { PermissionContext } from './context'

// ---------------------------------------------------------------------------
// Policy factory
// ---------------------------------------------------------------------------

/**
 * Creates a `PolicyEngine` pre-populated with the given roles.
 * Shorthand for `new PolicyEngine({ roles })` with optional extra options.
 *
 * @example
 * const policy = createTestPolicy([
 *   { name: 'USER', level: 1, permissions: ['posts:read'] },
 *   { name: 'ADMIN', level: 10, permissions: ['*'] },
 * ])
 */
export function createTestPolicy(
  roles: RoleDefinition[],
  opts?: Omit<PolicyOptions, 'roles'>,
): PolicyEngine {
  return new PolicyEngine({ ...opts, roles })
}

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

/**
 * Asserts that the context has the given permission (and optional condition).
 * Throws a descriptive error if the check fails — designed for use inside
 * `test()` / `it()` blocks in Vitest, Jest, or any other test runner.
 *
 * @example
 * const ctx = policy.createContext('USER')
 * expectCan(ctx, 'posts:read')
 */
export function expectCan(
  ctx: PermissionContext,
  permission: string,
  condition?: () => boolean,
): void {
  if (!ctx.can(permission, condition)) {
    const { reason } = ctx.canWithReason(permission)
    throw new Error(
      `expectCan failed: expected [${ctx.roles.join(', ')}] to have "${permission}"\n  Reason: ${reason}`,
    )
  }
}

/**
 * Asserts that the context does NOT have the given permission.
 * Throws a descriptive error if the context unexpectedly passes the check.
 *
 * @example
 * const ctx = policy.createContext('USER')
 * expectCannot(ctx, 'admin:delete')
 */
export function expectCannot(
  ctx: PermissionContext,
  permission: string,
  condition?: () => boolean,
): void {
  if (ctx.can(permission, condition)) {
    const { reason } = ctx.canWithReason(permission)
    throw new Error(
      `expectCannot failed: expected [${ctx.roles.join(', ')}] NOT to have "${permission}"\n  Reason: ${reason}`,
    )
  }
}

// ---------------------------------------------------------------------------
// Policy diff
// ---------------------------------------------------------------------------

export interface PolicyDiff {
  rolesAdded: string[]
  rolesRemoved: string[]
  /** Permissions that exist in `after` but not `before`, keyed by role. */
  permissionsGranted: Record<string, string[]>
  /** Permissions that exist in `before` but not `after`, keyed by role. */
  permissionsRevoked: Record<string, string[]>
}

/**
 * Returns a structured diff between two `PolicyEngine` snapshots.
 * Useful for asserting the exact changes made by a migration or test setup.
 *
 * @example
 * const before = createTestPolicy([{ name: 'USER', level: 1, permissions: ['posts:read'] }])
 * const after  = createTestPolicy([{ name: 'USER', level: 1, permissions: ['posts:read', 'posts:write'] }])
 * const diff = diffPolicies(before, after)
 * // diff.permissionsGranted → { USER: ['posts:write'] }
 */
export function diffPolicies(before: PolicyEngine, after: PolicyEngine): PolicyDiff {
  const beforeRoles = new Map(before.listRoles().map((r) => [r.name, r]))
  const afterRoles = new Map(after.listRoles().map((r) => [r.name, r]))

  const rolesAdded = [...afterRoles.keys()].filter((r) => !beforeRoles.has(r))
  const rolesRemoved = [...beforeRoles.keys()].filter((r) => !afterRoles.has(r))
  const permissionsGranted: Record<string, string[]> = {}
  const permissionsRevoked: Record<string, string[]> = {}

  for (const role of afterRoles.keys()) {
    if (!beforeRoles.has(role)) continue
    const beforePerms = new Set(before.getPermissions(role))
    const afterPerms = new Set(after.getPermissions(role))
    const granted = [...afterPerms].filter((p) => !beforePerms.has(p))
    const revoked = [...beforePerms].filter((p) => !afterPerms.has(p))
    if (granted.length) permissionsGranted[role] = granted
    if (revoked.length) permissionsRevoked[role] = revoked
  }

  return { rolesAdded, rolesRemoved, permissionsGranted, permissionsRevoked }
}
