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
   * Delegates to `engine.can(role, permission)`.
   */
  can(permission: string): boolean {
    return this.engine.can(this.role, permission)
  }

  /**
   * Returns `true` if the bound role does NOT have the given permission.
   * Delegates to `engine.cannot(role, permission)`.
   */
  cannot(permission: string): boolean {
    return this.engine.cannot(this.role, permission)
  }

  /**
   * Asserts that the bound role has the given permission.
   * Throws a `PermissionDeniedError` if the role lacks the permission.
   * Delegates to `engine.assert(role, permission)`.
   */
  assert(permission: string): void {
    this.engine.assert(this.role, permission)
  }

  /**
   * Returns `true` if the bound role's level is greater than or equal to
   * the level of `minRole`. Delegates to `engine.isAtLeast(role, minRole)`.
   */
  isAtLeast(minRole: string): boolean {
    return this.engine.isAtLeast(this.role, minRole)
  }
}
