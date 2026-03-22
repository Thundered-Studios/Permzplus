export type RoleLevel = number

export interface RoleDefinition {
  name: string
  level: RoleLevel
  permissions: string[]
}

export interface PolicyOptions {
  roles?: RoleDefinition[]
  permissions?: Record<string, string[]>
}

export interface ContextOptions {
  role: string
  userId?: string
  resourceId?: string
}

export interface PermzAdapter {
  getRoles(): Promise<RoleDefinition[]>
  getPermissions(role: string): Promise<string[]>
  saveRole(role: RoleDefinition): Promise<void>
  deleteRole(role: string): Promise<void>
  grantPermission(role: string, permission: string): Promise<void>
  revokePermission(role: string, permission: string): Promise<void>
}

/** Minimal interface exposed to PermissionContext — avoids circular imports. */
export interface IPolicyEngine {
  can(role: string, permission: string): boolean
  cannot(role: string, permission: string): boolean
  assert(role: string, permission: string): void
  getRoleLevel(role: string): number
  isAtLeast(role: string, minRole: string): boolean
}
