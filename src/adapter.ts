import type { PermzAdapter, RoleDefinition } from './types'

export abstract class BaseAdapter implements PermzAdapter {
  abstract getRoles(): Promise<RoleDefinition[]>
  abstract getPermissions(role: string): Promise<string[]>
  abstract saveRole(role: RoleDefinition): Promise<void>
  abstract deleteRole(role: string): Promise<void>
  abstract grantPermission(role: string, permission: string): Promise<void>
  abstract revokePermission(role: string, permission: string): Promise<void>
}

export class InMemoryAdapter extends BaseAdapter {
  private roles: Map<string, RoleDefinition> = new Map()
  private permissions: Map<string, Set<string>> = new Map()

  async getRoles(): Promise<RoleDefinition[]> {
    return Array.from(this.roles.values())
  }

  async getPermissions(role: string): Promise<string[]> {
    return Array.from(this.permissions.get(role) ?? [])
  }

  async saveRole(role: RoleDefinition): Promise<void> {
    this.roles.set(role.name, role)
  }

  async deleteRole(role: string): Promise<void> {
    this.roles.delete(role)
    this.permissions.delete(role)
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
}
