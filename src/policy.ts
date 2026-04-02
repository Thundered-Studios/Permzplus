import type {
  PolicyOptions,
  ContextOptions,
  RoleDefinition,
  PermzAdapter,
  IPolicyEngine,
  PolicyHooks,
  PolicySnapshot,
  PermissionCheckResult,
  AuditEvent,
  AuditLogger,
} from './types'
import { PermissionDeniedError, UnknownRoleError, InvalidPermissionError, AdapterError } from './errors'
import { validatePermission, matchesPermission } from './permissions'
import { PermissionContext } from './context'

export class PolicyEngine implements IPolicyEngine {
  private roles: Map<string, RoleDefinition>
  private denies: Map<string, Set<string>>
  private groups: Map<string, string[]>
  private adapter?: PermzAdapter
  private hooks: PolicyHooks
  private readonly debugMode: boolean
  private readonly auditLogger?: AuditLogger
  /** Cached resolved permission sets, keyed by role name. Cleared on any mutation. */
  private permCache: Map<string, Set<string>>

  constructor(options?: PolicyOptions) {
    this.roles = new Map()
    this.denies = new Map()
    this.groups = new Map()
    this.hooks = options?.hooks ?? {}
    this.debugMode = options?.debug ?? false
    this.auditLogger = options?.audit
    this.permCache = new Map()

    if (options?.roles) {
      for (const role of options.roles) {
        this.roles.set(role.name, { ...role, permissions: [...role.permissions] })
      }
    }

    if (options?.permissions) {
      for (const [roleName, perms] of Object.entries(options.permissions)) {
        const def = this.roles.get(roleName)
        if (!def) {
          throw new UnknownRoleError(roleName)
        }
        const existing = new Set(def.permissions)
        for (const perm of perms) {
          if (!validatePermission(perm)) {
            throw new InvalidPermissionError(perm)
          }
          if (!existing.has(perm)) {
            def.permissions.push(perm)
            existing.add(perm)
          }
        }
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Internal helpers
  // ---------------------------------------------------------------------------

  /**
   * Fires an adapter promise and routes any error to the `onAdapterError` hook
   * instead of letting it propagate. The in-memory state is always updated
   * synchronously before this is called, so a persistence failure does not
   * corrupt the engine — but callers should wire up `onAdapterError` to alert
   * or retry so the DB does not silently drift.
   */
  private fireAndForget(promise: Promise<void> | undefined, method: string): void {
    promise?.catch((err: unknown) => {
      this.hooks.onAdapterError?.(err instanceof Error ? err : new Error(String(err)), method)
    })
  }

  /** Fires an audit event. Errors from async loggers are swallowed to avoid disrupting callers. */
  private fireAudit(event: Omit<AuditEvent, 'timestamp'>): void {
    if (!this.auditLogger) return
    const full: AuditEvent = { ...event, timestamp: new Date() }
    const result = this.auditLogger.log(full)
    if (result instanceof Promise) {
      result.catch(() => { /* audit errors must not disrupt permission checks */ })
    }
  }

  /** Clears the entire permission cache. Called on every mutation. */
  private invalidateCache(): void {
    this.permCache.clear()
  }

  /**
   * Computes the full set of permissions for a role by collecting permissions
   * from all roles whose level is less than or equal to this role's level
   * (hierarchical inheritance), expanding any referenced permission groups,
   * then subtracting any explicit denies for the role.
   *
   * Results are memoised in `permCache` and cleared on every mutation.
   */
  private resolveEffectivePermissions(role: string): Set<string> {
    const cached = this.permCache.get(role)
    if (cached) return cached

    const def = this.roles.get(role)
    if (!def) {
      throw new UnknownRoleError(role)
    }

    const level = def.level
    const effective = new Set<string>()

    for (const [, roleDef] of this.roles) {
      if (roleDef.level <= level) {
        for (const perm of roleDef.permissions) {
          effective.add(perm)
        }
        if (roleDef.groups) {
          for (const groupName of roleDef.groups) {
            const groupPerms = this.groups.get(groupName)
            if (groupPerms) {
              for (const perm of groupPerms) {
                effective.add(perm)
              }
            }
          }
        }
      }
    }

    const denied = this.denies.get(role)
    if (denied) {
      for (const deniedPerm of denied) {
        for (const pattern of [...effective]) {
          if (matchesPermission(deniedPerm, pattern) || pattern === deniedPerm) {
            effective.delete(pattern)
          }
        }
      }
    }

    this.permCache.set(role, effective)
    return effective
  }

  /**
   * Returns the adapter, asserting it has user-role support (assignRole /
   * revokeRole / getUserRoles). Throws a descriptive AdapterError if either
   * condition is not met.
   */
  private requireUserAdapter(): PermzAdapter & Required<Pick<PermzAdapter, 'assignRole' | 'revokeRole' | 'getUserRoles'>> {
    if (!this.adapter) {
      throw new AdapterError(
        'No adapter configured. Call PolicyEngine.fromAdapter(adapter) to enable user-role methods.',
      )
    }
    if (
      typeof this.adapter.assignRole !== 'function' ||
      typeof this.adapter.revokeRole !== 'function' ||
      typeof this.adapter.getUserRoles !== 'function'
    ) {
      throw new AdapterError(
        'The current adapter does not support user-role assignment. ' +
          'Implement assignRole(), revokeRole(), and getUserRoles() on your adapter.',
      )
    }
    return this.adapter as PermzAdapter & Required<Pick<PermzAdapter, 'assignRole' | 'revokeRole' | 'getUserRoles'>>
  }

  // ---------------------------------------------------------------------------
  // Permission group API
  // ---------------------------------------------------------------------------

  /**
   * Registers a named permission group — a reusable set of permissions that
   * can be referenced from any role definition via the `groups` array.
   *
   * @throws {InvalidPermissionError} If any permission string is malformed.
   * @returns `this` for chaining.
   */
  defineGroup(name: string, permissions: string[]): this {
    for (const perm of permissions) {
      if (!validatePermission(perm)) {
        throw new InvalidPermissionError(perm)
      }
    }
    this.groups.set(name, [...permissions])
    this.invalidateCache()
    return this
  }

  // ---------------------------------------------------------------------------
  // Core permission checks
  // ---------------------------------------------------------------------------

  /**
   * Returns `true` if the given role has the specified permission, either directly
   * or through role-level inheritance. Wildcard patterns (e.g. `*`, `posts:*`) are
   * supported on the stored permission side.
   *
   * @throws {UnknownRoleError} If the role is not registered.
   * @throws {InvalidPermissionError} If the permission string is malformed.
   */
  can(role: string, permission: string): boolean {
    if (!this.roles.has(role)) {
      throw new UnknownRoleError(role)
    }
    if (!validatePermission(permission)) {
      throw new InvalidPermissionError(permission)
    }

    const effective = this.resolveEffectivePermissions(role)
    let result = false
    for (const pattern of effective) {
      if (matchesPermission(permission, pattern)) {
        result = true
        break
      }
    }

    if (this.debugMode) {
      const { reason } = this.canWithReason(role, permission)
      // eslint-disable-next-line no-console
      console.debug(`[permzplus] can("${role}", "${permission}") → ${result} | ${reason}`)
    }

    return result
  }

  /**
   * Returns `true` if the given role does NOT have the specified permission.
   *
   * @throws {UnknownRoleError} If the role is not registered.
   * @throws {InvalidPermissionError} If the permission string is malformed.
   */
  cannot(role: string, permission: string): boolean {
    return !this.can(role, permission)
  }

  /**
   * Asserts that the given role has the specified permission.
   *
   * @throws {PermissionDeniedError} If the role lacks the permission.
   * @throws {UnknownRoleError} If the role is not registered.
   * @throws {InvalidPermissionError} If the permission string is malformed.
   */
  assert(role: string, permission: string): void {
    if (!this.can(role, permission)) {
      throw new PermissionDeniedError(role, permission)
    }
  }

  /**
   * Returns `true` if the given role has ALL of the specified permissions.
   *
   * @throws {UnknownRoleError} If the role is not registered.
   * @throws {InvalidPermissionError} If any permission string is malformed.
   */
  canAll(role: string, permissions: string[]): boolean {
    return permissions.every((perm) => this.can(role, perm))
  }

  /**
   * Returns `true` if the given role has AT LEAST ONE of the specified permissions.
   *
   * @throws {UnknownRoleError} If the role is not registered.
   * @throws {InvalidPermissionError} If any permission string is malformed.
   */
  canAny(role: string, permissions: string[]): boolean {
    return permissions.some((perm) => this.can(role, perm))
  }

  /**
   * Asserts that the given role has ALL of the specified permissions.
   *
   * @throws {PermissionDeniedError} If the role lacks any permission.
   */
  assertAll(role: string, permissions: string[]): void {
    for (const perm of permissions) {
      if (!this.can(role, perm)) {
        throw new PermissionDeniedError(role, perm)
      }
    }
  }

  /**
   * Asserts that the given role has AT LEAST ONE of the specified permissions.
   *
   * @throws {PermissionDeniedError} If the role has none of the permissions.
   */
  assertAny(role: string, permissions: string[]): void {
    if (!this.canAny(role, permissions)) {
      throw new PermissionDeniedError(role, permissions.join(' | '))
    }
  }

  /**
   * Checks whether the given role has the specified permission and returns a
   * human-readable explanation of why the check passed or failed.
   *
   * @throws {UnknownRoleError} If the role is not registered.
   * @throws {InvalidPermissionError} If the permission string is malformed.
   */
  canWithReason(role: string, permission: string): PermissionCheckResult {
    if (!this.roles.has(role)) {
      throw new UnknownRoleError(role)
    }
    if (!validatePermission(permission)) {
      throw new InvalidPermissionError(permission)
    }

    const denied = this.denies.get(role)
    if (denied) {
      for (const deniedPerm of denied) {
        if (matchesPermission(permission, deniedPerm) || deniedPerm === permission) {
          return {
            result: false,
            reason: `Permission "${permission}" is explicitly denied for role "${role}"`,
          }
        }
      }
    }

    const roleDef = this.roles.get(role)!
    const sortedRoles = Array.from(this.roles.values())
      .filter((r) => r.level <= roleDef.level)
      .sort((a, b) => a.level - b.level)

    for (const source of sortedRoles) {
      for (const pattern of source.permissions) {
        if (matchesPermission(permission, pattern)) {
          const via = pattern !== permission ? ` via "${pattern}"` : ''
          const inherited = source.name !== role ? ` (inherited from "${source.name}")` : ''
          return {
            result: true,
            reason: `Permission "${permission}" granted${via} to role "${source.name}"${inherited}`,
          }
        }
      }
      if (source.groups) {
        for (const groupName of source.groups) {
          const groupPerms = this.groups.get(groupName) ?? []
          for (const pattern of groupPerms) {
            if (matchesPermission(permission, pattern)) {
              const via = pattern !== permission ? ` via "${pattern}"` : ''
              const inherited = source.name !== role ? ` (inherited from "${source.name}")` : ''
              return {
                result: true,
                reason: `Permission "${permission}" granted${via} through group "${groupName}" on role "${source.name}"${inherited}`,
              }
            }
          }
        }
      }
    }

    return {
      result: false,
      reason: `No permission matching "${permission}" found for role "${role}"`,
    }
  }

  // ---------------------------------------------------------------------------
  // Role introspection
  // ---------------------------------------------------------------------------

  /**
   * Returns the numeric level of the given role.
   *
   * @throws {UnknownRoleError} If the role is not registered.
   */
  getRoleLevel(role: string): number {
    const def = this.roles.get(role)
    if (!def) {
      throw new UnknownRoleError(role)
    }
    return def.level
  }

  /**
   * Returns `true` if the given role's level is greater than or equal to
   * the level of `minRole`.
   *
   * @throws {UnknownRoleError} If either role is not registered.
   */
  isAtLeast(role: string, minRole: string): boolean {
    return this.getRoleLevel(role) >= this.getRoleLevel(minRole)
  }

  /** Returns all registered role definitions. */
  listRoles(): RoleDefinition[] {
    return Array.from(this.roles.values()).map((r) => ({ ...r, permissions: [...r.permissions] }))
  }

  /**
   * Returns the full effective permission set for a role — all inherited
   * permissions and group expansions, minus any explicit denies.
   *
   * @throws {UnknownRoleError} If the role is not registered.
   */
  getPermissions(role: string): string[] {
    return Array.from(this.resolveEffectivePermissions(role))
  }

  // ---------------------------------------------------------------------------
  // Context creation
  // ---------------------------------------------------------------------------

  /**
   * Creates a short-lived `PermissionContext` bound to one or more roles.
   * When multiple roles are provided, `can` returns `true` if ANY satisfies
   * the check.
   *
   * @throws {UnknownRoleError} If any of the provided roles is not registered.
   */
  createContext(role: string | string[], opts?: Omit<ContextOptions, 'role' | 'roles'>): PermissionContext {
    const roles = Array.isArray(role) ? role : [role]
    for (const r of roles) {
      if (!this.roles.has(r)) {
        throw new UnknownRoleError(r)
      }
    }
    return new PermissionContext(roles, this, opts)
  }

  /**
   * Like `can()` but returns `false` instead of throwing for unknown or empty
   * roles. Safe to call for unauthenticated users.
   */
  safeCan(role: string, permission: string): boolean {
    if (!role || !this.roles.has(role)) return false
    try {
      return this.can(role, permission)
    } catch {
      return false
    }
  }

  /**
   * Like `createContext()` but returns a zero-permission context for unknown
   * or empty roles instead of throwing. Safe to use for unauthenticated users.
   */
  safeCreateContext(role: string | string[], opts?: Omit<ContextOptions, 'role' | 'roles'>): PermissionContext {
    const roles = Array.isArray(role) ? role : [role]
    const validRoles = roles.filter(r => r && this.roles.has(r))
    if (validRoles.length === 0) {
      return new PermissionContext([], this, opts)
    }
    return new PermissionContext(validRoles, this, opts)
  }

  /**
   * Returns the field names within `resource` that `role` is allowed to perform
   * `action` on. Looks for permissions in the format `resource.field:action`.
   *
   * @example
   * policy.addRole({ name: 'EDITOR', level: 1, permissions: ['post.title:edit', 'post.body:edit', 'post.status:read'] })
   * policy.permittedFieldsOf('EDITOR', 'post', 'edit') // → ['title', 'body']
   * policy.permittedFieldsOf('EDITOR', 'post', 'read') // → ['status']
   */
  permittedFieldsOf(role: string, resource: string, action: string): string[] {
    if (!role || !this.roles.has(role)) return []
    const prefix = `${resource}.`
    const suffix = `:${action}`
    const fields: string[] = []
    for (const perm of this.getPermissions(role)) {
      if (perm.startsWith(prefix) && perm.endsWith(suffix)) {
        const field = perm.slice(prefix.length, perm.length - suffix.length)
        if (field) fields.push(field)
      }
    }
    return fields
  }

  /**
   * Creates a `PermissionContext` for a user by fetching their assigned roles
   * from the adapter. Roles that no longer exist in the engine are silently
   * filtered out (stale assignment data).
   *
   * Requires an adapter with user-role support (`assignRole` / `getUserRoles`).
   *
   * @throws {AdapterError} If no adapter is configured or it lacks user-role methods.
   */
  async createUserContext(
    userId: string,
    tenantId?: string,
    opts?: Omit<ContextOptions, 'role' | 'roles' | 'userId' | 'tenantId'>,
  ): Promise<PermissionContext> {
    const adapter = this.requireUserAdapter()
    const allRoles = await adapter.getUserRoles(userId, tenantId)
    const validRoles = allRoles.filter((r) => this.roles.has(r))
    return new PermissionContext(validRoles, this, { ...opts, userId, tenantId })
  }

  // ---------------------------------------------------------------------------
  // Role mutation API
  // ---------------------------------------------------------------------------

  /**
   * Registers a new role (or replaces an existing one). All permissions in the
   * role definition are validated before storage.
   *
   * @throws {InvalidPermissionError} If any permission string in the role is malformed.
   * @returns `this` for chaining.
   */
  addRole(role: RoleDefinition): this {
    for (const perm of role.permissions) {
      if (!validatePermission(perm)) {
        throw new InvalidPermissionError(perm)
      }
    }

    this.roles.set(role.name, { ...role, permissions: [...role.permissions] })
    this.invalidateCache()
    this.hooks.onRoleAdd?.(role)
    this.fireAudit({ action: 'role.add', role: role.name })

    this.fireAndForget(this.adapter?.saveRole(role), 'saveRole')
    for (const perm of role.permissions) {
      this.fireAndForget(this.adapter?.grantPermission(role.name, perm), 'grantPermission')
    }

    return this
  }

  /**
   * Removes a role from the engine.
   *
   * @throws {UnknownRoleError} If the role is not registered.
   * @returns `this` for chaining.
   */
  removeRole(role: string): this {
    if (!this.roles.has(role)) {
      throw new UnknownRoleError(role)
    }

    this.roles.delete(role)
    this.denies.delete(role)
    this.invalidateCache()
    this.hooks.onRoleRemove?.(role)
    this.fireAudit({ action: 'role.remove', role })

    this.fireAndForget(this.adapter?.deleteRole(role), 'deleteRole')

    return this
  }

  /**
   * Grants an additional permission to an existing role.
   *
   * @throws {UnknownRoleError} If the role is not registered.
   * @throws {InvalidPermissionError} If the permission string is malformed.
   * @returns `this` for chaining.
   */
  grantTo(role: string, permission: string): this {
    const def = this.roles.get(role)
    if (!def) {
      throw new UnknownRoleError(role)
    }
    if (!validatePermission(permission)) {
      throw new InvalidPermissionError(permission)
    }

    const existing = new Set(def.permissions)
    if (!existing.has(permission)) {
      def.permissions.push(permission)
    }

    this.invalidateCache()
    this.hooks.onGrant?.(role, permission)
    this.fireAudit({ action: 'permission.grant', role, permission })
    this.fireAndForget(this.adapter?.grantPermission(role, permission), 'grantPermission')

    return this
  }

  /**
   * Revokes a previously granted permission from a role's own permission list.
   * Does not affect permissions inherited from lower-level roles.
   * This is a no-op if the role does not directly have the permission.
   *
   * @throws {UnknownRoleError} If the role is not registered.
   * @throws {InvalidPermissionError} If the permission string is malformed.
   * @returns `this` for chaining.
   */
  revokeFrom(role: string, permission: string): this {
    const def = this.roles.get(role)
    if (!def) {
      throw new UnknownRoleError(role)
    }
    if (!validatePermission(permission)) {
      throw new InvalidPermissionError(permission)
    }

    def.permissions = def.permissions.filter((p) => p !== permission)
    this.invalidateCache()
    this.hooks.onRevoke?.(role, permission)
    this.fireAudit({ action: 'permission.revoke', role, permission })
    this.fireAndForget(this.adapter?.revokePermission(role, permission), 'revokePermission')

    return this
  }

  /**
   * Explicitly denies a permission for a role, overriding any inherited grant.
   * The deny list is per-role and is not inherited by higher-level roles.
   *
   * @throws {UnknownRoleError} If the role is not registered.
   * @throws {InvalidPermissionError} If the permission string is malformed.
   * @returns `this` for chaining.
   */
  denyFrom(role: string, permission: string): this {
    if (!this.roles.has(role)) {
      throw new UnknownRoleError(role)
    }
    if (!validatePermission(permission)) {
      throw new InvalidPermissionError(permission)
    }

    if (!this.denies.has(role)) {
      this.denies.set(role, new Set())
    }
    this.denies.get(role)!.add(permission)

    this.permCache.delete(role)
    this.hooks.onDeny?.(role, permission)
    this.fireAudit({ action: 'permission.deny', role, permission })
    this.fireAndForget(this.adapter?.saveDeny(role, permission), 'saveDeny')

    return this
  }

  /**
   * Removes an explicit deny for a role+permission pair, restoring normal
   * inheritance behaviour. No-op if no such deny exists.
   *
   * @throws {UnknownRoleError} If the role is not registered.
   * @throws {InvalidPermissionError} If the permission string is malformed.
   * @returns `this` for chaining.
   */
  removeDeny(role: string, permission: string): this {
    if (!this.roles.has(role)) {
      throw new UnknownRoleError(role)
    }
    if (!validatePermission(permission)) {
      throw new InvalidPermissionError(permission)
    }

    this.denies.get(role)?.delete(permission)
    this.permCache.delete(role)
    this.hooks.onRemoveDeny?.(role, permission)
    this.fireAudit({ action: 'permission.removeDeny', role, permission })
    this.fireAndForget(this.adapter?.removeDeny(role, permission), 'removeDeny')

    return this
  }

  // ---------------------------------------------------------------------------
  // User-role assignment (requires adapter with user-role support)
  // ---------------------------------------------------------------------------

  /**
   * Assigns a role to a user. When `tenantId` is provided the assignment is
   * scoped to that tenant.
   *
   * @throws {UnknownRoleError} If `roleName` is not registered in the engine.
   * @throws {AdapterError} If no adapter is configured or it lacks user-role support.
   */
  async assignRole(userId: string, roleName: string, tenantId?: string): Promise<void> {
    if (!this.roles.has(roleName)) {
      throw new UnknownRoleError(roleName)
    }
    const adapter = this.requireUserAdapter()
    await adapter.assignRole(userId, roleName, tenantId)
    this.fireAudit({ action: 'user.assignRole', role: roleName, userId, tenantId })
  }

  /**
   * Revokes a role from a user.
   *
   * @throws {AdapterError} If no adapter is configured or it lacks user-role support.
   */
  async revokeRole(userId: string, roleName: string, tenantId?: string): Promise<void> {
    const adapter = this.requireUserAdapter()
    await adapter.revokeRole(userId, roleName, tenantId)
    this.fireAudit({ action: 'user.revokeRole', role: roleName, userId, tenantId })
  }

  /**
   * Returns all role names currently assigned to a user. Optionally filtered
   * by `tenantId` for multi-tenant setups.
   *
   * @throws {AdapterError} If no adapter is configured or it lacks user-role support.
   */
  async getUserRoles(userId: string, tenantId?: string): Promise<string[]> {
    const adapter = this.requireUserAdapter()
    return adapter.getUserRoles(userId, tenantId)
  }

  /**
   * Checks whether a user has the given permission across any of their
   * assigned roles. Roles that no longer exist in the engine are ignored.
   *
   * @throws {AdapterError} If no adapter is configured or it lacks user-role support.
   * @throws {InvalidPermissionError} If the permission string is malformed.
   */
  async canUser(userId: string, permission: string, tenantId?: string): Promise<boolean> {
    if (!validatePermission(permission)) {
      throw new InvalidPermissionError(permission)
    }
    const adapter = this.requireUserAdapter()
    const roles = await adapter.getUserRoles(userId, tenantId)
    return roles.some((r) => this.roles.has(r) && this.can(r, permission))
  }

  // ---------------------------------------------------------------------------
  // Bulk mutation API
  // ---------------------------------------------------------------------------

  /**
   * Registers multiple roles at once. Each role is validated and added
   * individually, so the first invalid role will throw without rolling back
   * previously added roles in the same call.
   *
   * @returns `this` for chaining.
   */
  addRoles(roles: RoleDefinition[]): this {
    for (const role of roles) {
      this.addRole(role)
    }
    return this
  }

  /**
   * Grants multiple permissions to a role in a single operation.
   * The permission cache is invalidated once after all grants are applied.
   *
   * @throws {UnknownRoleError} If the role is not registered.
   * @throws {InvalidPermissionError} If any permission string is malformed.
   * @returns `this` for chaining.
   */
  grantBulk(role: string, permissions: string[]): this {
    const def = this.roles.get(role)
    if (!def) throw new UnknownRoleError(role)
    for (const permission of permissions) {
      if (!validatePermission(permission)) throw new InvalidPermissionError(permission)
    }
    const existing = new Set(def.permissions)
    for (const permission of permissions) {
      if (!existing.has(permission)) {
        def.permissions.push(permission)
        existing.add(permission)
      }
      this.hooks.onGrant?.(role, permission)
      this.fireAudit({ action: 'permission.grant', role, permission })
      this.fireAndForget(this.adapter?.grantPermission(role, permission), 'grantPermission')
    }
    this.invalidateCache()
    return this
  }

  /**
   * Revokes multiple permissions from a role in a single operation.
   * Only removes permissions from the role's own list — inherited permissions
   * are unaffected.
   *
   * @throws {UnknownRoleError} If the role is not registered.
   * @throws {InvalidPermissionError} If any permission string is malformed.
   * @returns `this` for chaining.
   */
  revokeBulk(role: string, permissions: string[]): this {
    const def = this.roles.get(role)
    if (!def) throw new UnknownRoleError(role)
    for (const permission of permissions) {
      if (!validatePermission(permission)) throw new InvalidPermissionError(permission)
    }
    const toRemove = new Set(permissions)
    def.permissions = def.permissions.filter((p) => !toRemove.has(p))
    this.invalidateCache()
    for (const permission of permissions) {
      this.hooks.onRevoke?.(role, permission)
      this.fireAudit({ action: 'permission.revoke', role, permission })
      this.fireAndForget(this.adapter?.revokePermission(role, permission), 'revokePermission')
    }
    return this
  }

  /**
   * Explicitly denies multiple permissions for a role in a single operation.
   *
   * @throws {UnknownRoleError} If the role is not registered.
   * @throws {InvalidPermissionError} If any permission string is malformed.
   * @returns `this` for chaining.
   */
  denyBulk(role: string, permissions: string[]): this {
    if (!this.roles.has(role)) throw new UnknownRoleError(role)
    for (const permission of permissions) {
      if (!validatePermission(permission)) throw new InvalidPermissionError(permission)
    }
    if (!this.denies.has(role)) this.denies.set(role, new Set())
    const denySet = this.denies.get(role)!
    for (const permission of permissions) {
      denySet.add(permission)
      this.hooks.onDeny?.(role, permission)
      this.fireAudit({ action: 'permission.deny', role, permission })
      this.fireAndForget(this.adapter?.saveDeny(role, permission), 'saveDeny')
    }
    this.permCache.delete(role)
    return this
  }

  /**
   * Assigns multiple roles to a user in a single operation.
   * Roles that are not registered in the engine will throw `UnknownRoleError`
   * before any assignments are made.
   *
   * @throws {UnknownRoleError} If any role name is not registered.
   * @throws {AdapterError} If no adapter is configured or it lacks user-role support.
   */
  async assignRoles(userId: string, roleNames: string[], tenantId?: string): Promise<void> {
    for (const roleName of roleNames) {
      if (!this.roles.has(roleName)) throw new UnknownRoleError(roleName)
    }
    const adapter = this.requireUserAdapter()
    for (const roleName of roleNames) {
      await adapter.assignRole(userId, roleName, tenantId)
      this.fireAudit({ action: 'user.assignRole', role: roleName, userId, tenantId })
    }
  }

  /**
   * Revokes multiple roles from a user in a single operation.
   *
   * @throws {AdapterError} If no adapter is configured or it lacks user-role support.
   */
  async revokeRoles(userId: string, roleNames: string[], tenantId?: string): Promise<void> {
    const adapter = this.requireUserAdapter()
    for (const roleName of roleNames) {
      await adapter.revokeRole(userId, roleName, tenantId)
      this.fireAudit({ action: 'user.revokeRole', role: roleName, userId, tenantId })
    }
  }

  // ---------------------------------------------------------------------------
  // Serialisation / deserialisation
  // ---------------------------------------------------------------------------

  /**
   * Serialises the current in-memory policy state to a plain object.
   * Pass the result to `PolicyEngine.fromJSON()` to reconstruct an identical
   * engine. The adapter reference and hooks are NOT included.
   */
  toJSON(): PolicySnapshot {
    const denies: Record<string, string[]> = {}
    for (const [role, set] of this.denies) {
      denies[role] = Array.from(set)
    }

    const groups: Record<string, string[]> = {}
    for (const [name, perms] of this.groups) {
      groups[name] = [...perms]
    }

    return {
      roles: this.listRoles(),
      denies,
      groups,
    }
  }

  /**
   * Reconstructs a `PolicyEngine` from a snapshot produced by `toJSON()`.
   * The resulting engine is in-memory only — no adapter is attached.
   */
  static fromJSON(snapshot: PolicySnapshot): PolicyEngine {
    const engine = new PolicyEngine({ roles: snapshot.roles })

    for (const [name, perms] of Object.entries(snapshot.groups)) {
      engine.groups.set(name, [...perms])
    }

    for (const [role, perms] of Object.entries(snapshot.denies)) {
      engine.denies.set(role, new Set(perms))
    }

    return engine
  }

  /**
   * Creates a `PolicyEngine` backed by a persistent adapter. All roles, their
   * permissions, and any explicit denies are loaded from the adapter.
   *
   * @param adapter - A `PermzAdapter` implementation.
   * @returns A fully initialised `PolicyEngine` instance.
   */
  static async fromAdapter(adapter: PermzAdapter): Promise<PolicyEngine> {
    const engine = new PolicyEngine()
    engine.adapter = adapter

    const allRoles = await adapter.getRoles()

    for (const role of allRoles) {
      const perms = await adapter.getPermissions(role.name)
      engine.roles.set(role.name, {
        ...role,
        permissions: perms.length ? perms : role.permissions,
      })

      const denied = await adapter.getDeniedPermissions(role.name)
      if (denied.length) {
        engine.denies.set(role.name, new Set(denied))
      }
    }

    return engine
  }
}
