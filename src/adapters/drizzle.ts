import type { PermzAdapter, RoleDefinition } from '../types'
import { AdapterError } from '../errors'

// ---------------------------------------------------------------------------
// Schema interface
// ---------------------------------------------------------------------------

/**
 * References to the Drizzle table definitions that the consumer must create
 * in their own schema file and pass to {@link DrizzleAdapter}.
 *
 * **Recommended pg-core schema:**
 *
 * ```ts
 * import { pgTable, text, integer, serial, unique } from 'drizzle-orm/pg-core'
 *
 * export const permzRoles = pgTable('permz_roles', {
 *   name:  text('name').primaryKey(),
 *   level: integer('level').notNull(),
 * })
 *
 * export const permzPermissions = pgTable(
 *   'permz_permissions',
 *   {
 *     id:         serial('id').primaryKey(),
 *     roleName:   text('role_name').notNull().references(() => permzRoles.name, { onDelete: 'cascade' }),
 *     permission: text('permission').notNull(),
 *   },
 *   (t) => ({ uniq: unique().on(t.roleName, t.permission) }),
 * )
 *
 * export const permzDenies = pgTable(
 *   'permz_denies',
 *   {
 *     id:         serial('id').primaryKey(),
 *     roleName:   text('role_name').notNull().references(() => permzRoles.name, { onDelete: 'cascade' }),
 *     permission: text('permission').notNull(),
 *   },
 *   (t) => ({ uniq: unique().on(t.roleName, t.permission) }),
 * )
 *
 * // Required only if you use assignRole() / canUser() / createUserContext()
 * export const permzUserRoles = pgTable(
 *   'permz_user_roles',
 *   {
 *     id:       serial('id').primaryKey(),
 *     userId:   text('user_id').notNull(),
 *     roleName: text('role_name').notNull().references(() => permzRoles.name, { onDelete: 'cascade' }),
 *     tenantId: text('tenant_id').notNull().default(''),
 *   },
 *   (t) => ({ uniq: unique().on(t.userId, t.roleName, t.tenantId) }),
 * )
 * ```
 *
 * **Equivalent sqlite-core schema:** replace `pgTable`/`serial` with
 * `sqliteTable`/`integer('id').primaryKey({ autoIncrement: true })`.
 */
export interface PermzTables {
  /** Drizzle table reference for the roles table. */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  roles: any
  /** Drizzle table reference for the permissions table. */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  permissions: any
  /** Drizzle table reference for the denies table. */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  denies: any
  /**
   * Drizzle table reference for the user-roles table.
   * Optional — required only for `assignRole()`, `revokeRole()`, and
   * `getUserRoles()`. If absent those methods throw an `AdapterError`.
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  userRoles?: any
}

// ---------------------------------------------------------------------------
// Helper: lazy drizzle-orm import
// ---------------------------------------------------------------------------

async function drizzleOps(): Promise<{ eq: any; and: any }> {
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const mod: any = await import('drizzle-orm')
    return { eq: mod.eq, and: mod.and }
  } catch {
    throw new AdapterError(
      'DrizzleAdapter requires "drizzle-orm" to be installed. Run: npm install drizzle-orm',
    )
  }
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

/**
 * Drizzle ORM adapter for Permzplus.
 *
 * @example
 * ```ts
 * import { drizzle } from 'drizzle-orm/node-postgres'
 * import { DrizzleAdapter } from 'permzplus/adapters/drizzle'
 * import { permzRoles, permzPermissions, permzDenies, permzUserRoles } from './schema'
 *
 * const db = drizzle(pool)
 * const adapter = new DrizzleAdapter(db, {
 *   roles: permzRoles,
 *   permissions: permzPermissions,
 *   denies: permzDenies,
 *   userRoles: permzUserRoles, // optional, needed for user-role assignment
 * })
 * ```
 */
export class DrizzleAdapter implements PermzAdapter {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private readonly db: any
  private readonly tables: PermzTables

  constructor(db: unknown, tables: PermzTables) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    this.db = db as any
    this.tables = tables
  }

  // ---------------------------------------------------------------------------
  // Role definition methods
  // ---------------------------------------------------------------------------

  async getRoles(): Promise<RoleDefinition[]> {
    try {
      const roleRows: { name: string; level: number }[] = await this.db
        .select()
        .from(this.tables.roles)

      const definitions = await Promise.all(
        roleRows.map(async (row) => {
          const permissions = await this.getPermissions(row.name)
          return { name: row.name, level: row.level, permissions } satisfies RoleDefinition
        }),
      )
      return definitions
    } catch (err) {
      if (err instanceof AdapterError) throw err
      throw new AdapterError(`DrizzleAdapter.getRoles failed: ${(err as Error).message ?? err}`)
    }
  }

  async getPermissions(role: string): Promise<string[]> {
    try {
      const { eq } = await drizzleOps()
      const rows: { permission: string }[] = await this.db
        .select()
        .from(this.tables.permissions)
        .where(eq(this.tables.permissions.roleName, role))
      return rows.map((r) => r.permission)
    } catch (err) {
      if (err instanceof AdapterError) throw err
      throw new AdapterError(
        `DrizzleAdapter.getPermissions failed for role "${role}": ${(err as Error).message ?? err}`,
      )
    }
  }

  async saveRole(role: RoleDefinition): Promise<void> {
    try {
      await this.db
        .insert(this.tables.roles)
        .values({ name: role.name, level: role.level })
        .onConflictDoUpdate({ target: this.tables.roles.name, set: { level: role.level } })
    } catch (err) {
      if (err instanceof AdapterError) throw err
      throw new AdapterError(
        `DrizzleAdapter.saveRole failed for role "${role.name}": ${(err as Error).message ?? err}`,
      )
    }
  }

  async deleteRole(role: string): Promise<void> {
    try {
      const { eq } = await drizzleOps()
      await this.db.delete(this.tables.roles).where(eq(this.tables.roles.name, role))
    } catch (err) {
      if (err instanceof AdapterError) throw err
      throw new AdapterError(
        `DrizzleAdapter.deleteRole failed for role "${role}": ${(err as Error).message ?? err}`,
      )
    }
  }

  async grantPermission(role: string, permission: string): Promise<void> {
    try {
      await this.db
        .insert(this.tables.permissions)
        .values({ roleName: role, permission })
        .onConflictDoNothing()
    } catch (err) {
      if (err instanceof AdapterError) throw err
      throw new AdapterError(
        `DrizzleAdapter.grantPermission failed for role "${role}", permission "${permission}": ${(err as Error).message ?? err}`,
      )
    }
  }

  async revokePermission(role: string, permission: string): Promise<void> {
    try {
      const { eq, and } = await drizzleOps()
      await this.db
        .delete(this.tables.permissions)
        .where(
          and(
            eq(this.tables.permissions.roleName, role),
            eq(this.tables.permissions.permission, permission),
          ),
        )
    } catch (err) {
      if (err instanceof AdapterError) throw err
      throw new AdapterError(
        `DrizzleAdapter.revokePermission failed for role "${role}", permission "${permission}": ${(err as Error).message ?? err}`,
      )
    }
  }

  async getDeniedPermissions(role: string): Promise<string[]> {
    try {
      const { eq } = await drizzleOps()
      const rows: { permission: string }[] = await this.db
        .select()
        .from(this.tables.denies)
        .where(eq(this.tables.denies.roleName, role))
      return rows.map((r) => r.permission)
    } catch (err) {
      if (err instanceof AdapterError) throw err
      throw new AdapterError(
        `DrizzleAdapter.getDeniedPermissions failed for role "${role}": ${(err as Error).message ?? err}`,
      )
    }
  }

  async saveDeny(role: string, permission: string): Promise<void> {
    try {
      await this.db
        .insert(this.tables.denies)
        .values({ roleName: role, permission })
        .onConflictDoNothing()
    } catch (err) {
      if (err instanceof AdapterError) throw err
      throw new AdapterError(
        `DrizzleAdapter.saveDeny failed for role "${role}", permission "${permission}": ${(err as Error).message ?? err}`,
      )
    }
  }

  async removeDeny(role: string, permission: string): Promise<void> {
    try {
      const { eq, and } = await drizzleOps()
      await this.db
        .delete(this.tables.denies)
        .where(
          and(
            eq(this.tables.denies.roleName, role),
            eq(this.tables.denies.permission, permission),
          ),
        )
    } catch (err) {
      if (err instanceof AdapterError) throw err
      throw new AdapterError(
        `DrizzleAdapter.removeDeny failed for role "${role}", permission "${permission}": ${(err as Error).message ?? err}`,
      )
    }
  }

  // ---------------------------------------------------------------------------
  // User-role assignment methods
  // ---------------------------------------------------------------------------

  private requireUserRolesTable(): void {
    if (!this.tables.userRoles) {
      throw new AdapterError(
        'DrizzleAdapter: pass a "userRoles" table reference to PermzTables to enable user-role assignment.',
      )
    }
  }

  /**
   * Assigns a role to a user. Uses `onConflictDoNothing` so duplicate
   * assignments are a safe no-op.
   */
  async assignRole(userId: string, roleName: string, tenantId = ''): Promise<void> {
    this.requireUserRolesTable()
    try {
      await this.db
        .insert(this.tables.userRoles)
        .values({ userId, roleName, tenantId })
        .onConflictDoNothing()
    } catch (err) {
      if (err instanceof AdapterError) throw err
      throw new AdapterError(
        `DrizzleAdapter.assignRole failed for user "${userId}", role "${roleName}": ${(err as Error).message ?? err}`,
      )
    }
  }

  /** Revokes a role from a user. No-op if the assignment does not exist. */
  async revokeRole(userId: string, roleName: string, tenantId = ''): Promise<void> {
    this.requireUserRolesTable()
    try {
      const { eq, and } = await drizzleOps()
      await this.db
        .delete(this.tables.userRoles)
        .where(
          and(
            eq(this.tables.userRoles.userId, userId),
            eq(this.tables.userRoles.roleName, roleName),
            eq(this.tables.userRoles.tenantId, tenantId),
          ),
        )
    } catch (err) {
      if (err instanceof AdapterError) throw err
      throw new AdapterError(
        `DrizzleAdapter.revokeRole failed for user "${userId}", role "${roleName}": ${(err as Error).message ?? err}`,
      )
    }
  }

  /** Returns all role names assigned to a user, optionally filtered by tenant. */
  async getUserRoles(userId: string, tenantId = ''): Promise<string[]> {
    this.requireUserRolesTable()
    try {
      const { eq, and } = await drizzleOps()
      const rows: { roleName: string }[] = await this.db
        .select()
        .from(this.tables.userRoles)
        .where(
          and(
            eq(this.tables.userRoles.userId, userId),
            eq(this.tables.userRoles.tenantId, tenantId),
          ),
        )
      return rows.map((r) => r.roleName)
    } catch (err) {
      if (err instanceof AdapterError) throw err
      throw new AdapterError(
        `DrizzleAdapter.getUserRoles failed for user "${userId}": ${(err as Error).message ?? err}`,
      )
    }
  }
}
