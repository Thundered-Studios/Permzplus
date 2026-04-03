export type RoleLevel = number

export type { SubjectCondition, SubjectConditionFn, SubjectConditionObject } from './conditions'

// ---------------------------------------------------------------------------
// Audit logging
// ---------------------------------------------------------------------------

export type AuditAction =
  | 'role.add'
  | 'role.remove'
  | 'permission.grant'
  | 'permission.revoke'
  | 'permission.deny'
  | 'permission.removeDeny'
  | 'user.assignRole'
  | 'user.revokeRole'

export interface AuditEvent {
  action: AuditAction
  /** The role involved, if applicable. */
  role?: string
  /** The permission involved, if applicable. */
  permission?: string
  /** The user involved, if applicable (user-role assignment events). */
  userId?: string
  /** The tenant involved, if applicable. */
  tenantId?: string
  timestamp: Date
  /** Any extra metadata the caller wants to attach. */
  meta?: Record<string, unknown>
}

export interface AuditLogger {
  log(event: AuditEvent): void | Promise<void>
}

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
  /**
   * Optional audit logger. Called after every policy mutation with a
   * structured `AuditEvent`. Use `InMemoryAuditLogger` in tests or wire in
   * your own implementation to persist to a database.
   */
  audit?: AuditLogger
}

export interface DelegateOptions {
  /** Restrict delegated access to only these permissions (whitelist). If omitted, all delegatee permissions apply. */
  scope?: string[]
  /** Optional metadata stored on the context for audit purposes. */
  delegatedBy?: string
}

export interface ContextOptions {
  role?: string
  /** Multiple roles — `can` returns true if ANY role satisfies the check. */
  roles?: string[]
  userId?: string
  resourceId?: string
  /** Optional tenant ID for multi-tenant scoping. */
  tenantId?: string
  /**
   * Arbitrary user attributes forwarded to function conditions as `ctx.user`.
   * Enables ABAC+ patterns like `(resource, ctx) => ctx.user.dept === resource.dept`.
   */
  user?: Record<string, unknown>
}

export interface RoleAssignment {
  role: string
  expiresAt?: Date
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
  assignRole?(userId: string, roleName: string, tenantId?: string, options?: { expiresAt?: Date }): Promise<void>

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
  can(role: string, permission: string, subject?: unknown, ctx?: Record<string, unknown>): boolean
  cannot(role: string, permission: string, subject?: unknown, ctx?: Record<string, unknown>): boolean
  assert(role: string, permission: string, subject?: unknown, ctx?: Record<string, unknown>): void
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
  /** Like `can()` but returns `false` instead of throwing for unknown/empty roles. */
  safeCan(role: string, permission: string): boolean
  /** Returns field names within `resource` that `role` can perform `action` on (via `resource.field:action` permissions). */
  permittedFieldsOf(role: string, resource: string, action: string): string[]
  /** Returns a copy of `obj` containing only the fields `role` is allowed to `action` on `resource`. */
  filterFields(role: string, obj: Record<string, unknown>, resource: string, action: string): Record<string, unknown>
  /**
   * Returns all conditions (function and object) registered for a role+permission pair
   * via `defineRule()`. Used by `accessibleBy()` to build database WHERE clauses.
   */
  getConditionsFor(role: string, permission: string): Array<import('./conditions').SubjectCondition>
}
