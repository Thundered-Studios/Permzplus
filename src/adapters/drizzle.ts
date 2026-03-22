import type { PermzAdapter, RoleDefinition } from '../types'
import { AdapterError } from '../errors'

// ---------------------------------------------------------------------------
// Schema interface
// ---------------------------------------------------------------------------

/**
 * References to the two Drizzle table definitions that the consumer must
 * create in their own schema file and pass to {@link DrizzleAdapter}.
 *
 * Because `drizzle-orm` is an optional peer dependency, Permzplus does not
 * define the tables internally. Instead, consumers should define them once
 * using the appropriate Drizzle table factory for their database dialect and
 * then pass the resulting table objects here.
 *
 * **Recommended pg-core schema (copy-paste into your schema file):**
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
 * ```
 *
 * **Equivalent sqlite-core schema:**
 *
 * ```ts
 * import { sqliteTable, text, integer, unique } from 'drizzle-orm/sqlite-core'
 *
 * export const permzRoles = sqliteTable('permz_roles', {
 *   name:  text('name').primaryKey(),
 *   level: integer('level').notNull(),
 * })
 *
 * export const permzPermissions = sqliteTable(
 *   'permz_permissions',
 *   {
 *     id:         integer('id').primaryKey({ autoIncrement: true }),
 *     roleName:   text('role_name').notNull().references(() => permzRoles.name, { onDelete: 'cascade' }),
 *     permission: text('permission').notNull(),
 *   },
 *   (t) => ({ uniq: unique().on(t.roleName, t.permission) }),
 * )
 * ```
 */
export interface PermzTables {
  /** Drizzle table reference for the roles table (e.g. `permzRoles`). */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  roles: any
  /** Drizzle table reference for the permissions table (e.g. `permzPermissions`). */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  permissions: any
}

// ---------------------------------------------------------------------------
// Helper: lazy drizzle-orm import
// ---------------------------------------------------------------------------

/**
 * Dynamically imports `drizzle-orm` and returns the helpers needed for
 * building WHERE clauses. Throws {@link AdapterError} with a clear message
 * when the package is not installed so that end-users know exactly what to do.
 */
async function drizzleOps(): Promise<{ eq: any; and: any }> {
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const mod: any = await import('drizzle-orm')
    return { eq: mod.eq, and: mod.and }
  } catch {
    throw new AdapterError(
      'DrizzleAdapter requires "drizzle-orm" to be installed. ' +
        'Run: npm install drizzle-orm',
    )
  }
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

/**
 * Drizzle ORM adapter for Permzplus.
 *
 * Persists roles and permissions using a Drizzle `db` instance and explicit
 * table references supplied by the consumer. Because Drizzle is schema-first
 * and supports multiple SQL dialects (PostgreSQL, SQLite, MySQL), the library
 * cannot bundle its own table definitions — the consumer must define the
 * tables once and pass them via {@link PermzTables}.
 *
 * `drizzle-orm` itself is an optional peer dependency and is imported
 * dynamically at runtime; if it is absent a descriptive {@link AdapterError}
 * is thrown.
 *
 * @example
 * ```ts
 * import { drizzle } from 'drizzle-orm/node-postgres'
 * import { DrizzleAdapter, PermzTables } from 'permzplus/adapters/drizzle'
 * import { permzRoles, permzPermissions } from './schema'
 * import { Pool } from 'pg'
 *
 * const pool = new Pool({ connectionString: process.env.DATABASE_URL })
 * const db   = drizzle(pool)
 *
 * const tables: PermzTables = { roles: permzRoles, permissions: permzPermissions }
 * const adapter = new DrizzleAdapter(db, tables)
 * ```
 */
export class DrizzleAdapter implements PermzAdapter {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private readonly db: any
  private readonly tables: PermzTables

  /**
   * @param db     - A Drizzle database instance (e.g. the return value of
   *                 `drizzle(pool)` or `drizzle(client)`).
   * @param tables - References to the two Drizzle table objects that map to
   *                 the roles and permissions tables. See {@link PermzTables}.
   */
  constructor(db: unknown, tables: PermzTables) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    this.db = db as any
    this.tables = tables
  }

  // ---------------------------------------------------------------------------
  // PermzAdapter implementation
  // ---------------------------------------------------------------------------

  /**
   * Retrieves all roles together with their associated permissions.
   *
   * Executes two queries: one to fetch every role row, then — in parallel —
   * one `getPermissions` call per role. For small-to-medium role catalogs
   * (typically fewer than a hundred entries) this is straightforward and
   * avoids the need for a join with manual result grouping.
   *
   * @returns An array of {@link RoleDefinition} objects.
   */
  async getRoles(): Promise<RoleDefinition[]> {
    try {
      const roleRows: { name: string; level: number }[] = await this.db
        .select()
        .from(this.tables.roles)

      const definitions = await Promise.all(
        roleRows.map(async (row) => {
          const permissions = await this.getPermissions(row.name)
          return {
            name: row.name,
            level: row.level,
            permissions,
          } satisfies RoleDefinition
        }),
      )

      return definitions
    } catch (err) {
      if (err instanceof AdapterError) throw err
      throw new AdapterError(
        `DrizzleAdapter.getRoles failed: ${(err as Error).message ?? err}`,
      )
    }
  }

  /**
   * Retrieves all permissions granted to a specific role.
   *
   * @param role - The name of the role whose permissions should be fetched.
   * @returns An array of permission strings belonging to the role.
   */
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

  /**
   * Creates or updates a role record in the database.
   *
   * Only the role name and level are persisted here. Permissions are managed
   * separately via {@link grantPermission} and {@link revokePermission}.
   *
   * Uses `onConflictDoUpdate` so the call is idempotent — re-saving a role
   * with a new level simply updates the existing row.
   *
   * @param role - The {@link RoleDefinition} to upsert. The `permissions`
   *   array on the definition is ignored; use {@link grantPermission} to
   *   persist individual permissions.
   */
  async saveRole(role: RoleDefinition): Promise<void> {
    try {
      await this.db
        .insert(this.tables.roles)
        .values({ name: role.name, level: role.level })
        .onConflictDoUpdate({
          target: this.tables.roles.name,
          set: { level: role.level },
        })
    } catch (err) {
      if (err instanceof AdapterError) throw err
      throw new AdapterError(
        `DrizzleAdapter.saveRole failed for role "${role.name}": ${(err as Error).message ?? err}`,
      )
    }
  }

  /**
   * Deletes a role from the database.
   *
   * Associated permission rows are removed automatically via the
   * `onDelete: 'cascade'` foreign-key constraint defined on the permissions
   * table (see {@link PermzTables} for the recommended schema).
   *
   * @param role - The name of the role to delete.
   */
  async deleteRole(role: string): Promise<void> {
    try {
      const { eq } = await drizzleOps()

      await this.db
        .delete(this.tables.roles)
        .where(eq(this.tables.roles.name, role))
    } catch (err) {
      if (err instanceof AdapterError) throw err
      throw new AdapterError(
        `DrizzleAdapter.deleteRole failed for role "${role}": ${(err as Error).message ?? err}`,
      )
    }
  }

  /**
   * Grants a permission to a role, creating the record if it does not already
   * exist.
   *
   * Uses `onConflictDoNothing` so that granting a permission that is already
   * present is a safe no-op — it will not throw a unique-constraint violation.
   *
   * @param role       - The name of the role to grant the permission to.
   * @param permission - The permission string to grant.
   */
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

  /**
   * Revokes a permission from a role.
   *
   * The operation is a no-op when the `(roleName, permission)` pair does not
   * exist — Drizzle's `delete` simply affects zero rows without throwing.
   *
   * @param role       - The name of the role to revoke the permission from.
   * @param permission - The permission string to revoke.
   */
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
}
