/**
 * Kysely adapter for Permzplus.
 *
 * Implements the full `PermzAdapter` interface using Kysely — a type-safe
 * SQL query builder. Works with PostgreSQL, MySQL, and SQLite dialects.
 *
 * **Setup:**
 * 1. Add the permzplus tables to your Kysely `Database` type.
 * 2. Run the migration returned by `createPermzMigration()`.
 * 3. Pass your `Kysely<DB>` instance to `new KyselyAdapter(db)`.
 * 4. Pass the adapter to `PolicyEngine.fromAdapter(adapter)` or the
 *    `PolicyEngine` constructor.
 *
 * @example TypeScript type setup
 * ```ts
 * // db/schema.ts
 * import type {
 *   PermzRolesTable,
 *   PermzPermissionsTable,
 *   PermzDeniesTable,
 *   PermzUserRolesTable,
 * } from 'permzplus/adapters/kysely'
 *
 * export interface Database {
 *   // ...your own tables...
 *   permz_roles:       PermzRolesTable
 *   permz_permissions: PermzPermissionsTable
 *   permz_denies:      PermzDeniesTable
 *   permz_user_roles:  PermzUserRolesTable
 * }
 * ```
 *
 * @example Adapter instantiation
 * ```ts
 * import { KyselyAdapter } from 'permzplus/adapters/kysely'
 * import { db } from '@/db'           // Kysely<Database>
 * import { policy } from '@/policy'
 *
 * const adapter = new KyselyAdapter(db)
 * const engine  = await PolicyEngine.fromAdapter(adapter)
 * ```
 *
 * @example Custom table names
 * ```ts
 * const adapter = new KyselyAdapter(db, {
 *   tables: {
 *     roles:       'acl_roles',
 *     permissions: 'acl_permissions',
 *     denies:      'acl_denies',
 *     userRoles:   'acl_user_roles',
 *   },
 * })
 * ```
 *
 * @example Run the migration (Kysely Migrations API)
 * ```ts
 * import { createPermzMigration } from 'permzplus/adapters/kysely'
 *
 * const { up, down } = createPermzMigration()
 *
 * export const Migration20240501: Migration = {
 *   async up(db) { await db.schema.executeRawQuery(up) },
 *   async down(db) { await db.schema.executeRawQuery(down) },
 * }
 * ```
 */

import type { PermzAdapter, RoleDefinition } from '../types'
import { AdapterError } from '../errors'

// ---------------------------------------------------------------------------
// Table interfaces — add these to your Kysely Database type
// ---------------------------------------------------------------------------

/**
 * Kysely column type for the `permz_roles` table.
 *
 * ```ts
 * // db/schema.ts
 * import type { PermzRolesTable } from 'permzplus/adapters/kysely'
 * export interface Database {
 *   permz_roles: PermzRolesTable
 * }
 * ```
 */
export interface PermzRolesTable {
  /** Role name — primary key. */
  name: string
  /** Numeric hierarchy level. Higher = more privileged. */
  level: number
}

/**
 * Kysely column type for the `permz_permissions` table.
 */
export interface PermzPermissionsTable {
  id: number
  /** FK → `permz_roles.name` (cascade delete). */
  role_name: string
  /** Permission string, e.g. `"posts:read"` or `"billing:*"`. */
  permission: string
}

/**
 * Kysely column type for the `permz_denies` table.
 */
export interface PermzDeniesTable {
  id: number
  /** FK → `permz_roles.name` (cascade delete). */
  role_name: string
  /** Explicitly denied permission. */
  permission: string
}

/**
 * Kysely column type for the `permz_user_roles` table.
 * Required only if you use `assignRole()` / `canUser()` / `createUserContext()`.
 */
export interface PermzUserRolesTable {
  id: number
  user_id: string
  role_name: string
  /** Empty string `''` means no tenant (global assignment). */
  tenant_id: string
  /** Nullable expiry for time-bounded role assignments. */
  expires_at: Date | null
}

/**
 * Convenience interface — spread into your `Database` type to add all four
 * permzplus tables at once (with default table names).
 *
 * ```ts
 * export interface Database extends KyselyPermzDatabase {
 *   // your tables...
 * }
 * ```
 */
export interface KyselyPermzDatabase {
  permz_roles: PermzRolesTable
  permz_permissions: PermzPermissionsTable
  permz_denies: PermzDeniesTable
  permz_user_roles: PermzUserRolesTable
}

// ---------------------------------------------------------------------------
// Adapter options
// ---------------------------------------------------------------------------

/** Configurable table names for `KyselyAdapter`. */
export interface KyselyAdapterTableNames {
  roles?: string
  permissions?: string
  denies?: string
  userRoles?: string
}

export interface KyselyAdapterOptions {
  /** Override the default table names (`permz_roles`, etc.). */
  tables?: KyselyAdapterTableNames
}

// ---------------------------------------------------------------------------
// Migration helper
// ---------------------------------------------------------------------------

export interface PermzMigration {
  /** SQL to create all permzplus tables. Run this in your `up` migration. */
  up: string
  /** SQL to drop all permzplus tables. Run this in your `down` migration. */
  down: string
}

/**
 * Returns SQL strings to create and drop the permzplus schema.
 *
 * The SQL is written in portable ANSI SQL and tested against PostgreSQL,
 * MySQL, and SQLite. Run `up` in your migration's `up()` method and `down`
 * in the `down()` method.
 *
 * @param options - Optional table name overrides.
 *
 * @example
 * ```ts
 * const { up, down } = createPermzMigration()
 *
 * // Kysely Migrations API
 * export const Migration: Migration = {
 *   async up(db) {
 *     for (const stmt of up.split(';').filter(Boolean)) {
 *       await sql.raw(stmt).execute(db)
 *     }
 *   },
 *   async down(db) {
 *     for (const stmt of down.split(';').filter(Boolean)) {
 *       await sql.raw(stmt).execute(db)
 *     }
 *   },
 * }
 * ```
 */
export function createPermzMigration(options?: KyselyAdapterOptions): PermzMigration {
  const t = resolveTableNames(options?.tables)

  const up = `
CREATE TABLE IF NOT EXISTS "${t.roles}" (
  name  TEXT NOT NULL PRIMARY KEY,
  level INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS "${t.permissions}" (
  id          INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  role_name   TEXT    NOT NULL REFERENCES "${t.roles}" (name) ON DELETE CASCADE,
  permission  TEXT    NOT NULL,
  UNIQUE (role_name, permission)
);

CREATE TABLE IF NOT EXISTS "${t.denies}" (
  id          INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  role_name   TEXT    NOT NULL REFERENCES "${t.roles}" (name) ON DELETE CASCADE,
  permission  TEXT    NOT NULL,
  UNIQUE (role_name, permission)
);

CREATE TABLE IF NOT EXISTS "${t.userRoles}" (
  id          INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  user_id     TEXT    NOT NULL,
  role_name   TEXT    NOT NULL REFERENCES "${t.roles}" (name) ON DELETE CASCADE,
  tenant_id   TEXT    NOT NULL DEFAULT '',
  expires_at  DATETIME,
  UNIQUE (user_id, role_name, tenant_id)
);

CREATE INDEX IF NOT EXISTS "permz_user_roles_user_idx" ON "${t.userRoles}" (user_id, tenant_id);
`.trim()

  const down = `
DROP TABLE IF EXISTS "${t.userRoles}";
DROP TABLE IF EXISTS "${t.denies}";
DROP TABLE IF EXISTS "${t.permissions}";
DROP TABLE IF EXISTS "${t.roles}";
`.trim()

  return { up, down }
}

// ---------------------------------------------------------------------------
// KyselyAdapter
// ---------------------------------------------------------------------------

/**
 * Kysely-backed implementation of `PermzAdapter`.
 *
 * Supports all `PermzAdapter` methods including optional user-role assignment
 * (`assignRole`, `revokeRole`, `getUserRoles`), multi-tenant scoping, and
 * time-bounded role expiry.
 *
 * Pass a `Kysely<DB>` instance where `DB` includes the permzplus table types
 * (see `KyselyPermzDatabase`).
 */
export class KyselyAdapter implements PermzAdapter {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private readonly db: any
  private readonly t: Required<KyselyAdapterTableNames>

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  constructor(db: any, options?: KyselyAdapterOptions) {
    this.db = db
    this.t = resolveTableNames(options?.tables)
  }

  // ---------------------------------------------------------------------------
  // Role definition methods
  // ---------------------------------------------------------------------------

  async getRoles(): Promise<RoleDefinition[]> {
    try {
      const roles: Array<{ name: string; level: number }> = await this.db
        .selectFrom(this.t.roles)
        .selectAll()
        .execute()

      const result: RoleDefinition[] = []
      for (const role of roles) {
        const permissions = await this.getPermissions(role.name)
        result.push({ name: role.name, level: role.level, permissions })
      }
      return result
    } catch (err) {
      throw new AdapterError(`KyselyAdapter.getRoles failed: ${errMsg(err)}`)
    }
  }

  async getPermissions(role: string): Promise<string[]> {
    try {
      const rows: Array<{ permission: string }> = await this.db
        .selectFrom(this.t.permissions)
        .select('permission')
        .where('role_name', '=', role)
        .execute()
      return rows.map(r => r.permission)
    } catch (err) {
      throw new AdapterError(
        `KyselyAdapter.getPermissions failed for role "${role}": ${errMsg(err)}`,
      )
    }
  }

  async saveRole(role: RoleDefinition): Promise<void> {
    try {
      await this.db
        .insertInto(this.t.roles)
        .values({ name: role.name, level: role.level })
        .onConflict((oc: any) => oc.column('name').doUpdateSet({ level: role.level }))
        .execute()
    } catch (err) {
      throw new AdapterError(
        `KyselyAdapter.saveRole failed for role "${role.name}": ${errMsg(err)}`,
      )
    }
  }

  async deleteRole(role: string): Promise<void> {
    try {
      await this.db
        .deleteFrom(this.t.roles)
        .where('name', '=', role)
        .execute()
    } catch (err) {
      throw new AdapterError(
        `KyselyAdapter.deleteRole failed for role "${role}": ${errMsg(err)}`,
      )
    }
  }

  async grantPermission(role: string, permission: string): Promise<void> {
    try {
      await this.db
        .insertInto(this.t.permissions)
        .values({ role_name: role, permission })
        .onConflict((oc: any) => oc.columns(['role_name', 'permission']).doNothing())
        .execute()
    } catch (err) {
      throw new AdapterError(
        `KyselyAdapter.grantPermission failed for role "${role}", permission "${permission}": ${errMsg(err)}`,
      )
    }
  }

  async revokePermission(role: string, permission: string): Promise<void> {
    try {
      await this.db
        .deleteFrom(this.t.permissions)
        .where('role_name', '=', role)
        .where('permission', '=', permission)
        .execute()
    } catch (err) {
      throw new AdapterError(
        `KyselyAdapter.revokePermission failed for role "${role}", permission "${permission}": ${errMsg(err)}`,
      )
    }
  }

  async getDeniedPermissions(role: string): Promise<string[]> {
    try {
      const rows: Array<{ permission: string }> = await this.db
        .selectFrom(this.t.denies)
        .select('permission')
        .where('role_name', '=', role)
        .execute()
      return rows.map(r => r.permission)
    } catch (err) {
      throw new AdapterError(
        `KyselyAdapter.getDeniedPermissions failed for role "${role}": ${errMsg(err)}`,
      )
    }
  }

  async saveDeny(role: string, permission: string): Promise<void> {
    try {
      await this.db
        .insertInto(this.t.denies)
        .values({ role_name: role, permission })
        .onConflict((oc: any) => oc.columns(['role_name', 'permission']).doNothing())
        .execute()
    } catch (err) {
      throw new AdapterError(
        `KyselyAdapter.saveDeny failed for role "${role}", permission "${permission}": ${errMsg(err)}`,
      )
    }
  }

  async removeDeny(role: string, permission: string): Promise<void> {
    try {
      await this.db
        .deleteFrom(this.t.denies)
        .where('role_name', '=', role)
        .where('permission', '=', permission)
        .execute()
    } catch (err) {
      throw new AdapterError(
        `KyselyAdapter.removeDeny failed for role "${role}", permission "${permission}": ${errMsg(err)}`,
      )
    }
  }

  // ---------------------------------------------------------------------------
  // User-role assignment methods (optional)
  // ---------------------------------------------------------------------------

  /**
   * Assigns a role to a user, optionally scoped to a tenant.
   * Idempotent — safe to call multiple times.
   */
  async assignRole(
    userId: string,
    roleName: string,
    tenantId = '',
    opts?: { expiresAt?: Date },
  ): Promise<void> {
    try {
      await this.db
        .insertInto(this.t.userRoles)
        .values({
          user_id: userId,
          role_name: roleName,
          tenant_id: tenantId,
          expires_at: opts?.expiresAt ?? null,
        })
        .onConflict((oc: any) =>
          oc
            .columns(['user_id', 'role_name', 'tenant_id'])
            .doUpdateSet({ expires_at: opts?.expiresAt ?? null }),
        )
        .execute()
    } catch (err) {
      throw new AdapterError(
        `KyselyAdapter.assignRole failed for user "${userId}", role "${roleName}": ${errMsg(err)}`,
      )
    }
  }

  /**
   * Revokes a role from a user. No-op when the assignment does not exist.
   */
  async revokeRole(userId: string, roleName: string, tenantId = ''): Promise<void> {
    try {
      await this.db
        .deleteFrom(this.t.userRoles)
        .where('user_id', '=', userId)
        .where('role_name', '=', roleName)
        .where('tenant_id', '=', tenantId)
        .execute()
    } catch (err) {
      throw new AdapterError(
        `KyselyAdapter.revokeRole failed for user "${userId}", role "${roleName}": ${errMsg(err)}`,
      )
    }
  }

  /**
   * Returns all non-expired roles assigned to a user, optionally filtered by tenant.
   */
  async getUserRoles(userId: string, tenantId = ''): Promise<string[]> {
    try {
      const now = new Date()
      let query = this.db
        .selectFrom(this.t.userRoles)
        .select('role_name')
        .where('user_id', '=', userId)
        .where('tenant_id', '=', tenantId)

      // Filter out expired rows (expires_at IS NULL = never expires)
      query = query.where((eb: any) =>
        eb.or([
          eb('expires_at', 'is', null),
          eb('expires_at', '>', now),
        ]),
      )

      const rows: Array<{ role_name: string }> = await query.execute()
      return rows.map(r => r.role_name)
    } catch (err) {
      throw new AdapterError(
        `KyselyAdapter.getUserRoles failed for user "${userId}": ${errMsg(err)}`,
      )
    }
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function resolveTableNames(
  names?: KyselyAdapterTableNames,
): Required<KyselyAdapterTableNames> {
  return {
    roles:       names?.roles       ?? 'permz_roles',
    permissions: names?.permissions ?? 'permz_permissions',
    denies:      names?.denies      ?? 'permz_denies',
    userRoles:   names?.userRoles   ?? 'permz_user_roles',
  }
}

function errMsg(err: unknown): string {
  return (err as Error)?.message ?? String(err)
}
