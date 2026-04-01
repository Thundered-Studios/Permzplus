export type RoleLevel = number

export interface RoleDefinition {
  name: string
  level: RoleLevel
  permissions: string[]
  /** Optional permission group names to include in this role's effective permissions. */
  groups?: string[]
}

/** Snapshot shape produced by `PolicyEngine.toJSON()` and consumed by `PolicyEngine.fromJSON()`. */
export interface PolicySnapshot {
  roles: RoleDefinition[]
  denies: Record<string, string[]>
  groups: Record<string, string[]>
}

/** Result returned by `canWithReason` — includes the boolean outcome and a human-readable explanation. */
export interface PermissionCheckResult {
  result: boolean
  reason: string
}

/**
 * Lifecycle hooks fired on every policy mutation. All hooks are optional.
 * Hooks are synchronous and called after the in-memory state has been updated.
 */
export interface PolicyHooks {
  onRoleAdd?: (role: RoleDefinition) => void
  onRoleRemove?: (role: string) => void
  onGrant?: (role: string, permission: string) => void
  onRevoke?: (role: string, permission: string) => void
  onDeny?: (role: string, permission: string) => void
  onRemoveDeny?: (role: string, permission: string) => void
  /**
   * Called when an adapter write fails. Use this to log or alert.
   * The in-memory state has already been updated successfully — only the
   * persistence layer failed.
   */
  onAdapterError?: (err: Error, method: string) => void
}

export interface PolicyOptions {
  roles?: RoleDefinition[]
  permissions?: Record<string, string[]>
  /** Optional lifecycle hooks called after each mutation. */
  hooks?: PolicyHooks
  /**
   * When true, logs every permission check result to `console.debug`.
   * Useful for tracing "why can't this user do X?" in development.
   */
  debug?: boolean
}

export interface ContextOptions {
  role?: string
  /** Multiple roles — `can` returns true if ANY role satisfies the check. */
  roles?: string[]
  userId?: string
  resourceId?: string
  /** Optional tenant ID for multi-tenant scoping. */
  tenantId?: string
}

/**
 * Core adapter interface for persisting role definitions and permissions.
 *
 * The three optional user-role methods (`assignRole`, `revokeRole`, `getUserRoles`)
 * unlock `PolicyEngine.assignRole()`, `revokeRole()`, `canUser()`, and
 * `createUserContext()`. Adapters that do not implement them will cause those
 * methods to throw an `AdapterError` with a descriptive message.
 */
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
  /** Removes an explicit deny for a role+permission pair. */
  removeDeny(role: string, permission: string): Promise<void>

  // -------------------------------------------------------------------------
  // Optional user-role assignment methods
  // -------------------------------------------------------------------------

  /**
   * Assigns a role to a user. When `tenantId` is provided the assignment is
   * scoped to that tenant, enabling multi-tenant role isolation.
   *
   * Implement this (along with `revokeRole` and `getUserRoles`) to enable
   * `PolicyEngine.assignRole()`, `revokeRole()`, `canUser()`, and
   * `createUserContext()`.
   */
  assignRole?(userId: string, roleName: string, tenantId?: string): Promise<void>

  /**
   * Revokes a role from a user.
   * Optional — see `assignRole`.
   */
  revokeRole?(userId: string, roleName: string, tenantId?: string): Promise<void>

  /**
   * Returns all role names assigned to a user, optionally filtered by tenant.
   * Optional — see `assignRole`.
   */
  getUserRoles?(userId: string, tenantId?: string): Promise<string[]>
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
  /** Returns true if the role has ALL of the given permissions, throws otherwise. */
  assertAll(role: string, permissions: string[]): void
  /** Returns true if the role has ANY of the given permissions, throws otherwise. */
  assertAny(role: string, permissions: string[]): void
  /** Checks permission and returns a human-readable reason for the outcome. */
  canWithReason(role: string, permission: string): PermissionCheckResult
  /** Returns all registered role definitions. */
  listRoles(): RoleDefinition[]
  /** Returns the full effective permission set for a role (inherited + groups, minus denies). */
  getPermissions(role: string): string[]
}
