import type { PolicyOptions, ContextOptions, RoleDefinition, PermzAdapter, IPolicyEngine } from './types'
import { BUILT_IN_ROLES } from './roles'
import { PermissionDeniedError, UnknownRoleError, InvalidPermissionError } from './errors'
import { validatePermission, matchesPermission } from './permissions'
import { PermissionContext } from './context'

export class PolicyEngine implements IPolicyEngine {
  private roles: Map<string, RoleDefinition>
  private denies: Map<string, Set<string>>
  private adapter?: PermzAdapter

  constructor(options?: PolicyOptions) {
    this.roles = new Map()
    this.denies = new Map()

    if (options?.roles) {
      for (const role of options.roles) {
        this.roles.set(role.name, { ...role, permissions: [...role.permissions] })
      }
    }

    // Apply per-role permission additions from options.permissions
    if (options?.permissions) {
      for (const [roleName, perms] of Object.entries(options.permissions)) {
        const def = this.roles.get(roleName)
        if (!def) {
          throw new UnknownRoleError(roleName)
        }
        // Dedupe: add only permissions not already present
        const existing = new Set(def.permissions)
        for (const perm of perms) {
          if (!existing.has(perm)) {
            def.permissions.push(perm)
            existing.add(perm)
          }
        }
      }
    }
  }

  /**
   * Computes the full set of permissions for a role by collecting permissions
   * from all roles whose level is less than or equal to this role's level
   * (hierarchical inheritance), then subtracting any explicit denies for the role.
   */
  private getEffectivePermissions(role: string): Set<string> {
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
      }
    }

    // Remove explicitly denied permissions for this role
    const denied = this.denies.get(role)
    if (denied) {
      for (const perm of denied) {
        effective.delete(perm)
      }
    }

    return effective
  }

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

    const effective = this.getEffectivePermissions(role)
    for (const pattern of effective) {
      if (matchesPermission(permission, pattern)) {
        return true
      }
    }
    return false
  }

  /**
   * Returns `true` if the given role does NOT have the specified permission.
   * The inverse of `can`.
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

  /**
   * Creates a short-lived `PermissionContext` bound to the given role and this
   * engine. Useful for per-request permission checking without repeating the role
   * argument on every call.
   *
   * @throws {UnknownRoleError} If the role is not registered.
   */
  createContext(role: string, opts?: Omit<ContextOptions, 'role'>): PermissionContext {
    if (!this.roles.has(role)) {
      throw new UnknownRoleError(role)
    }
    return new PermissionContext(role, this, opts)
  }

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

    // Fire-and-forget adapter persistence
    this.adapter?.saveRole(role)
    for (const perm of role.permissions) {
      this.adapter?.grantPermission(role.name, perm)
    }

    return this
  }

  /**
   * Grants an additional permission to an existing role. The permission is added
   * in a deduplicated fashion.
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

    // Fire-and-forget adapter persistence
    this.adapter?.grantPermission(role, permission)

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

    // Fire-and-forget adapter persistence
    this.adapter?.revokePermission(role, permission)

    return this
  }

  /**
   * Creates a `PolicyEngine` backed by a persistent adapter. Built-in roles that
   * do not yet exist in the adapter's store are seeded automatically. All roles
   * and their permissions are then loaded from the adapter into the engine.
   *
   * @param adapter - A `PermzAdapter` implementation (e.g. database-backed).
   * @returns A fully initialised `PolicyEngine` instance.
   */
  static async fromAdapter(adapter: PermzAdapter): Promise<PolicyEngine> {
    const engine = new PolicyEngine()
    engine.adapter = adapter

    // Retrieve what the adapter already knows about
    const adapterRoles = await adapter.getRoles()
    const adapterRoleNames = new Set(adapterRoles.map((r) => r.name))

    // Seed built-in roles that are not yet persisted
    for (const builtIn of BUILT_IN_ROLES) {
      if (!adapterRoleNames.has(builtIn.name)) {
        await adapter.saveRole(builtIn)
        for (const perm of builtIn.permissions) {
          await adapter.grantPermission(builtIn.name, perm)
        }
      }
    }

    // Reload the full role list from the adapter (includes freshly seeded roles)
    const allRoles = await adapter.getRoles()

    for (const role of allRoles) {
      const perms = await adapter.getPermissions(role.name)
      engine.roles.set(role.name, {
        ...role,
        permissions: perms.length ? perms : role.permissions,
      })
    }

    return engine
  }
}
