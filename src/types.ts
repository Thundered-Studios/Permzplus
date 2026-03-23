export type RoleLevel = number

export interface RoleDefinition {
  name: string
  level: RoleLevel
  permissions: string[]
  /** Optional permission group names to include in this role's effective permissions. */
  groups?: string[]
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
  /** Returns all explicitly denied permissions for a role. */
  getDeniedPermissions(role: string): Promise<string[]>
  /** Persists an explicit deny for a role+permission pair. */
  saveDeny(role: string, permission: string): Promise<void>
}

/** Minimal interface exposed to PermissionContext — avoids circular imports. */
export interface IPolicyEngine {
  can(role: string, permission: string): boolean
  cannot(role: string, permission: string): boolean
  assert(role: string, permission: string): void
  getRoleLevel(role: string): number
  isAtLeast(role: string, minRole: string): boolean
  /** Returns true if the role has ALL of the given permissions. */
  canAll(role: string, permissions: string[]): boolean
  /** Returns true if the role has ANY of the given permissions. */
  canAny(role: string, permissions: string[]): boolean
  /** Returns all registered role definitions. */
  listRoles(): RoleDefinition[]
  /** Returns the full effective permission set for a role (inherited + groups, minus denies). */
  getPermissions(role: string): string[]
}
