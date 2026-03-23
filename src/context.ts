import { IPolicyEngine, ContextOptions } from './types'
import { PermissionDeniedError } from './errors'

/**
 * A short-lived per-request object that binds a role to a policy engine reference.
 * Provides a convenient API for checking and asserting permissions within a single
 * request lifecycle without repeating the role argument on every call.
 */
export class PermissionContext {
  /** The role this context is bound to. */
  readonly role: string

  /** Optional user ID associated with this context. */
  readonly userId?: string

  /** Optional resource ID associated with this context. */
  readonly resourceId?: string

  private engine: IPolicyEngine

  constructor(
    role: string,
    engine: IPolicyEngine,
    opts?: Omit<ContextOptions, 'role'>
  ) {
    this.role = role
    this.engine = engine
    this.userId = opts?.userId
    this.resourceId = opts?.resourceId
  }

  /**
   * Returns `true` if the bound role has the given permission.
   * An optional `condition` function can enforce resource-level rules on top of
   * the role check — if provided, both the permission check AND the condition
   * must pass for `can` to return `true`.
   *
   * @example
   * // Resource-ownership check
   * ctx.can('posts:edit', () => post.authorId === ctx.userId)
   */
  can(permission: string, condition?: () => boolean): boolean {
    const hasPermission = this.engine.can(this.role, permission)
    if (!hasPermission) return false
    if (condition !== undefined) return condition()
    return true
  }

  /**
   * Returns `true` if the bound role does NOT have the given permission,
   * or if the optional condition fails.
   */
  cannot(permission: string, condition?: () => boolean): boolean {
    return !this.can(permission, condition)
  }

  /**
   * Asserts that the bound role has the given permission (and that the optional
   * condition passes). Throws a `PermissionDeniedError` if either check fails.
   */
  assert(permission: string, condition?: () => boolean): void {
    if (!this.can(permission, condition)) {
      throw new PermissionDeniedError(this.role, permission)
    }
  }

  /**
   * Returns `true` if the bound role has ALL of the given permissions.
   * An optional `condition` is evaluated only when all permission checks pass.
   */
  canAll(permissions: string[], condition?: () => boolean): boolean {
    const allPass = this.engine.canAll(this.role, permissions)
    if (!allPass) return false
    if (condition !== undefined) return condition()
    return true
  }

  /**
   * Returns `true` if the bound role has AT LEAST ONE of the given permissions.
   * An optional `condition` is evaluated only when at least one permission check passes.
   */
  canAny(permissions: string[], condition?: () => boolean): boolean {
    const anyPass = this.engine.canAny(this.role, permissions)
    if (!anyPass) return false
    if (condition !== undefined) return condition()
    return true
  }

  /**
   * Returns `true` if the bound role's level is greater than or equal to
   * the level of `minRole`. Delegates to `engine.isAtLeast(role, minRole)`.
   */
  isAtLeast(minRole: string): boolean {
    return this.engine.isAtLeast(this.role, minRole)
  }
}
