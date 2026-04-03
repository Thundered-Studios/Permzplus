import type { PermzAdapter, RoleDefinition, RoleAssignment } from './types'

export abstract class BaseAdapter implements PermzAdapter {
  abstract getRoles(): Promise<RoleDefinition[]>
  abstract getPermissions(role: string): Promise<string[]>
  abstract saveRole(role: RoleDefinition): Promise<void>
  abstract deleteRole(role: string): Promise<void>
  abstract grantPermission(role: string, permission: string): Promise<void>
  abstract revokePermission(role: string, permission: string): Promise<void>
  abstract getDeniedPermissions(role: string): Promise<string[]>
  abstract saveDeny(role: string, permission: string): Promise<void>
  abstract removeDeny(role: string, permission: string): Promise<void>
}

/**
 * Default in-memory adapter. No external dependencies required.
 *
 * Fully implements the optional user-role assignment methods (`assignRole`,
 * `revokeRole`, `getUserRoles`), enabling `PolicyEngine.canUser()`,
 * `assignRole()`, and `createUserContext()` without a database.
 *
 * User-role assignments support an optional `tenantId` for multi-tenant
 * isolation — different tenants can assign different roles to the same user.
 */
export class InMemoryAdapter extends BaseAdapter {
  private roles: Map<string, RoleDefinition> = new Map()
  private permissions: Map<string, Set<string>> = new Map()
  private denies: Map<string, Set<string>> = new Map()
  /**
   * User-role assignment store.
   * Key format: `"<tenantId>:<userId>"` (tenantId defaults to `""` when absent).
   * Value: map of role name -> assignment metadata (including optional expiry).
   */
  private userRoles: Map<string, Map<string, RoleAssignment>> = new Map()

  // ---------------------------------------------------------------------------
  // Role definition methods
  // ---------------------------------------------------------------------------

  async getRoles(): Promise<RoleDefinition[]> {
    return Array.from(this.roles.values())
  }

  async getPermissions(role: string): Promise<string[]> {
    return Array.from(this.permissions.get(role) ?? [])
  }

  async saveRole(role: RoleDefinition): Promise<void> {
    this.roles.set(role.name, role)
    this.permissions.set(role.name, new Set(role.permissions))
  }

  async deleteRole(role: string): Promise<void> {
    this.roles.delete(role)
    this.permissions.delete(role)
    this.denies.delete(role)
  }

  async grantPermission(role: string, permission: string): Promise<void> {
    if (!this.permissions.has(role)) {
      this.permissions.set(role, new Set())
    }
    this.permissions.get(role)!.add(permission)
  }

  async revokePermission(role: string, permission: string): Promise<void> {
    this.permissions.get(role)?.delete(permission)
  }

  async getDeniedPermissions(role: string): Promise<string[]> {
    return Array.from(this.denies.get(role) ?? [])
  }

  async saveDeny(role: string, permission: string): Promise<void> {
    if (!this.denies.has(role)) {
      this.denies.set(role, new Set())
    }
    this.denies.get(role)!.add(permission)
  }

  async removeDeny(role: string, permission: string): Promise<void> {
    this.denies.get(role)?.delete(permission)
  }

  // ---------------------------------------------------------------------------
  // User-role assignment methods
  // ---------------------------------------------------------------------------

  private userKey(userId: string, tenantId?: string): string {
    return `${tenantId ?? ''}:${userId}`
  }

  /**
   * Assigns a role to a user. When `tenantId` is provided the assignment is
   * scoped to that tenant so two tenants can give the same user different roles.
   * When `options.expiresAt` is provided, the assignment will be automatically
   * filtered out after that date.
   */
  async assignRole(userId: string, roleName: string, tenantId?: string, options?: { expiresAt?: Date }): Promise<void> {
    const key = this.userKey(userId, tenantId)
    if (!this.userRoles.has(key)) {
      this.userRoles.set(key, new Map())
    }
    this.userRoles.get(key)!.set(roleName, { role: roleName, expiresAt: options?.expiresAt })
  }

  /** Revokes a role from a user. No-op if the assignment does not exist. */
  async revokeRole(userId: string, roleName: string, tenantId?: string): Promise<void> {
    const key = this.userKey(userId, tenantId)
    this.userRoles.get(key)?.delete(roleName)
  }

  /** Returns all roles assigned to the user, optionally scoped to a tenant. Expired assignments are filtered out. */
  async getUserRoles(userId: string, tenantId?: string): Promise<string[]> {
    const key = this.userKey(userId, tenantId)
    const assignments = this.userRoles.get(key)
    if (!assignments) return []
    const now = new Date()
    const roles: string[] = []
    for (const [roleName, assignment] of assignments) {
      if (!assignment.expiresAt || assignment.expiresAt >= now) {
        roles.push(roleName)
      }
    }
    return roles
  }

  /**
   * Removes all expired role assignments from the internal store.
   * Useful for periodic cleanup to prevent unbounded memory growth.
   */
  cleanExpiredAssignments(): void {
    const now = new Date()
    for (const assignments of this.userRoles.values()) {
      for (const [roleName, assignment] of assignments) {
        if (assignment.expiresAt && assignment.expiresAt < now) {
          assignments.delete(roleName)
        }
      }
    }
  }
}
