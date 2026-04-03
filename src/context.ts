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
  /**
   * Context object forwarded to function conditions in `defineRule()`.
   * Automatically includes `userId` and `tenantId` from context options.
   */
  private readonly conditionCtx: Record<string, unknown>

  constructor(
    roles: string | string[],
    engine: IPolicyEngine,
    opts?: Omit<ContextOptions, 'role' | 'roles'>
  ) {
    this.roles = Array.isArray(roles) ? roles : [roles]
    this.engine = engine
    this.userId = opts?.userId
    this.resourceId = opts?.resourceId
    this.conditionCtx = {
      ...(opts?.userId !== undefined ? { userId: opts.userId } : {}),
      ...(opts?.tenantId !== undefined ? { tenantId: opts.tenantId } : {}),
    }
  }

  /**
   * Returns `true` if ANY of the bound roles has the given permission.
   *
   * Accepts two optional arguments for ABAC:
   * - `subject` — the resource being accessed (e.g. a post object). When provided,
   *   any conditions registered via `defineRule()` are evaluated against it.
   * - `condition` — a lightweight runtime check applied on top of the role+subject
   *   check (e.g. ownership guard). Both must pass for `can` to return `true`.
   *
   * @example Subject-aware (uses defineRule conditions)
   * ```ts
   * ctx.can('posts:edit', post)
   * ```
   *
   * @example Runtime condition callback (legacy, still supported)
   * ```ts
   * ctx.can('posts:edit', () => post.authorId === ctx.userId)
   * ```
   *
   * @example Both
   * ```ts
   * ctx.can('posts:edit', post, () => extraCheck())
   * ```
   */
  can(permission: string, subjectOrCondition?: unknown | (() => boolean), condition?: () => boolean): boolean {
    // Detect legacy single-callback overload: can('perm', () => bool)
    if (typeof subjectOrCondition === 'function') {
      const hasPermission = this.roles.some((r) => this.engine.can(r, permission))
      if (!hasPermission) return false
      return (subjectOrCondition as () => boolean)()
    }

    // Subject-aware path
    const subject = subjectOrCondition
    const hasPermission = this.roles.some((r) => this.engine.can(r, permission, subject, this.conditionCtx))
    if (!hasPermission) return false
    if (condition !== undefined) return condition()
    return true
  }

  /**
   * Returns `true` if NONE of the bound roles has the given permission,
   * or if the optional condition/subject check fails.
   */
  cannot(permission: string, subjectOrCondition?: unknown | (() => boolean), condition?: () => boolean): boolean {
    return !this.can(permission, subjectOrCondition as unknown, condition)
  }

  /**
   * Asserts that at least one of the bound roles has the given permission.
   * Throws a `PermissionDeniedError` if the check fails.
   */
  assert(permission: string, subjectOrCondition?: unknown | (() => boolean), condition?: () => boolean): void {
    if (!this.can(permission, subjectOrCondition as unknown, condition)) {
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
   * Returns a copy of `obj` containing only the fields that ANY of the bound
   * roles is allowed to perform `action` on within `resource`.
   */
  filterFields(obj: Record<string, unknown>, resource: string, action: string): Record<string, unknown> {
    const allowed = new Set<string>()
    for (const r of this.roles) {
      for (const f of this.engine.permittedFieldsOf(r, resource, action)) allowed.add(f)
    }
    const out: Record<string, unknown> = {}
    for (const k of Object.keys(obj)) if (allowed.has(k)) out[k] = obj[k]
    return out
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
