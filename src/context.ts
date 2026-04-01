import type { IPolicyEngine, ContextOptions, PermissionCheckResult } from './types'
import { PermissionDeniedError } from './errors'

/**
 * A short-lived per-request object that binds one or more roles to a policy
 * engine reference. When multiple roles are provided, permission checks return
 * `true` if ANY of the roles satisfies the check.
 *
 * Provides a convenient API for checking and asserting permissions within a
 * single request lifecycle without repeating the role argument on every call.
 */
export class PermissionContext {
  /**
   * All roles this context was created with. `can` returns `true` if any of
   * these roles has the queried permission.
   */
  readonly roles: string[]

  /**
   * The primary role — the first entry in `roles`. Kept for backward
   * compatibility with single-role usage.
   */
  get role(): string {
    return this.roles[0]
  }

  /** Optional user ID associated with this context. */
  readonly userId?: string

  /** Optional resource ID associated with this context. */
  readonly resourceId?: string

  private engine: IPolicyEngine

  constructor(
    roles: string | string[],
    engine: IPolicyEngine,
    opts?: Omit<ContextOptions, 'role' | 'roles'>
  ) {
    this.roles = Array.isArray(roles) ? roles : [roles]
    this.engine = engine
    this.userId = opts?.userId
    this.resourceId = opts?.resourceId
  }

  /**
   * Returns `true` if ANY of the bound roles has the given permission.
   * An optional `condition` function can enforce resource-level rules on top of
   * the role check — if provided, both the permission check AND the condition
   * must pass for `can` to return `true`.
   *
   * @example
   * // Resource-ownership check
   * ctx.can('posts:edit', () => post.authorId === ctx.userId)
   */
  can(permission: string, condition?: () => boolean): boolean {
    const hasPermission = this.roles.some((r) => this.engine.can(r, permission))
    if (!hasPermission) return false
    if (condition !== undefined) return condition()
    return true
  }

  /**
   * Returns `true` if NONE of the bound roles has the given permission,
   * or if the optional condition fails.
   */
  cannot(permission: string, condition?: () => boolean): boolean {
    return !this.can(permission, condition)
  }

  /**
   * Asserts that at least one of the bound roles has the given permission (and
   * that the optional condition passes). Throws a `PermissionDeniedError` if
   * either check fails.
   */
  assert(permission: string, condition?: () => boolean): void {
    if (!this.can(permission, condition)) {
      throw new PermissionDeniedError(this.roles.join(' | '), permission)
    }
  }

  /**
   * Returns `true` if ANY of the bound roles has ALL of the given permissions.
   * An optional `condition` is evaluated only when all permission checks pass.
   */
  canAll(permissions: string[], condition?: () => boolean): boolean {
    const allPass = this.roles.some((r) => this.engine.canAll(r, permissions))
    if (!allPass) return false
    if (condition !== undefined) return condition()
    return true
  }

  /**
   * Returns `true` if ANY of the bound roles has AT LEAST ONE of the given permissions.
   * An optional `condition` is evaluated only when at least one permission check passes.
   */
  canAny(permissions: string[], condition?: () => boolean): boolean {
    const anyPass = this.roles.some((r) => this.engine.canAny(r, permissions))
    if (!anyPass) return false
    if (condition !== undefined) return condition()
    return true
  }

  /**
   * Asserts that at least one of the bound roles has ALL of the given permissions.
   *
   * @throws {PermissionDeniedError} If no role satisfies all permissions.
   */
  assertAll(permissions: string[], condition?: () => boolean): void {
    if (!this.canAll(permissions, condition)) {
      throw new PermissionDeniedError(this.roles.join(' | '), permissions.join(' & '))
    }
  }

  /**
   * Asserts that at least one of the bound roles has at least one of the given
   * permissions.
   *
   * @throws {PermissionDeniedError} If no role has any of the permissions.
   */
  assertAny(permissions: string[], condition?: () => boolean): void {
    if (!this.canAny(permissions, condition)) {
      throw new PermissionDeniedError(this.roles.join(' | '), permissions.join(' | '))
    }
  }

  /**
   * Checks the permission against the primary role and returns a
   * `PermissionCheckResult` with a human-readable reason. For multi-role
   * contexts this checks the first role that returns `true`, or the primary
   * role when the check fails.
   */
  canWithReason(permission: string): PermissionCheckResult {
    for (const r of this.roles) {
      const result = this.engine.canWithReason(r, permission)
      if (result.result) return result
    }
    // Return the explanation for the primary role when all fail
    return this.engine.canWithReason(this.roles[0], permission)
  }

  /**
   * Returns `true` if ANY of the bound roles has a level greater than or equal
   * to the level of `minRole`.
   */
  isAtLeast(minRole: string): boolean {
    return this.roles.some((r) => this.engine.isAtLeast(r, minRole))
  }
}
