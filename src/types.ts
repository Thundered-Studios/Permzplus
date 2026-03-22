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
