import type { PermzAdapter, RoleDefinition } from '../types'
import { AdapterError } from '../errors'

// Static drizzle-orm imports used by the ABAC filter generator below.
// drizzle-orm is a peer dependency — tsup externalises it automatically,
// so these lines add ZERO bytes to the permzplus bundle.
import {
  and, or, not,
  eq, ne, gt, gte, lt, lte,
  inArray, notInArray,
  isNull, isNotNull,
  like, between,
  sql,
} from 'drizzle-orm'
import type { SQL } from 'drizzle-orm'
import { accessibleBy } from '../query'
import type { SubjectConditionObject } from '../conditions'

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

// ---------------------------------------------------------------------------
// ABAC Filter Generator
// ---------------------------------------------------------------------------
//
// Converts permzplus MongoDB-style conditions into Drizzle SQL expressions
// that can be passed directly to .where().
//
// drizzle-orm operators are peer-dependency imports (see top of file) —
// they are fully externalized by tsup and add zero bytes to the bundle.
// ---------------------------------------------------------------------------

/** Minimal policy engine interface required by drizzleFilter(). */
interface QueryEngine {
  can(role: string, permission: string): boolean
  getConditionsFor(role: string, permission: string): unknown[]
}

/**
 * Result returned by {@link drizzleFilter}.
 *
 * | State | `permitted` | `unrestricted` | `filter` |
 * |---|---|---|---|
 * | No permission | `false` | `false` | `sql\`1=0\`` |
 * | Allowed, no conditions | `true` | `true` | `undefined` |
 * | Allowed, with conditions | `true` | `false` | Drizzle SQL expression |
 */
export interface DrizzleFilterResult {
  /**
   * Drop this directly into `.where(filter)`.
   *
   * - `undefined`  → unrestricted (no clause needed — Drizzle ignores undefined)
   * - `sql\`1=0\`` → no permission (zero rows returned)
   * - SQL expr     → AND/OR combination of the ABAC conditions
   */
  filter: SQL | undefined
  /** `false` when the role has no permission — you can skip the DB call entirely. */
  permitted: boolean
  /** `true` when permitted with zero conditions — all records are accessible. */
  unrestricted: boolean
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyCol = any

/**
 * Converts a single field value spec to a Drizzle SQL clause.
 * Handles implicit equality and all MongoDB-style operators.
 * @internal
 */
function fieldToSql(col: AnyCol, rawValue: unknown): SQL | undefined {
  // Implicit equality: { status: 'published' }
  if (rawValue === null || typeof rawValue !== 'object') {
    return eq(col, rawValue) as SQL
  }

  const ops = rawValue as Record<string, unknown>
  const parts: (SQL | undefined)[] = []

  for (const op in ops) {
    const operand = ops[op]
    switch (op) {
      case '$eq':  parts.push(eq(col, operand) as SQL); break
      case '$ne':  parts.push(ne(col, operand) as SQL); break
      case '$gt':  parts.push(gt(col, operand) as SQL); break
      case '$gte': parts.push(gte(col, operand) as SQL); break
      case '$lt':  parts.push(lt(col, operand) as SQL); break
      case '$lte': parts.push(lte(col, operand) as SQL); break
      case '$in':
        parts.push(inArray(col, operand as unknown[]) as SQL)
        break
      case '$nin':
        parts.push(notInArray(col, operand as unknown[]) as SQL)
        break
      case '$exists':
        parts.push((operand ? isNotNull(col) : isNull(col)) as SQL)
        break
      case '$regex': {
        // Convert regex to a LIKE pattern (best-effort for simple patterns).
        // Complex regexes need a raw sql`` expression in the calling code.
        const src = operand instanceof RegExp ? operand.source : String(operand)
        parts.push(like(col, src) as SQL)
        break
      }
      case '$between': {
        if (Array.isArray(operand) && operand.length === 2) {
          parts.push(between(col, operand[0], operand[1]) as SQL)
        }
        break
      }
      // Unknown operators are silently skipped — they have no SQL equivalent.
    }
  }

  if (parts.length === 0) return undefined
  if (parts.length === 1) return parts[0]
  return and(...parts) as SQL
}

/**
 * Recursively converts a MongoDB-style condition object to a Drizzle SQL
 * expression. Field names are looked up as column properties on `table`.
 * @internal
 */
function conditionToSql<TTable extends Record<string, unknown>>(
  condition: SubjectConditionObject,
  table: TTable,
): SQL | undefined {
  const parts: (SQL | undefined)[] = []

  for (const key in condition) {
    const value = condition[key]

    if (key === '$and') {
      if (!Array.isArray(value)) continue
      const sub = (value as SubjectConditionObject[])
        .map((c) => conditionToSql(c, table))
        .filter(Boolean) as SQL[]
      if (sub.length > 0) parts.push(and(...sub) as SQL)
    } else if (key === '$or') {
      if (!Array.isArray(value)) continue
      const sub = (value as SubjectConditionObject[])
        .map((c) => conditionToSql(c, table))
        .filter(Boolean) as SQL[]
      if (sub.length > 0) parts.push(or(...sub) as SQL)
    } else if (key === '$nor') {
      if (!Array.isArray(value)) continue
      const sub = (value as SubjectConditionObject[])
        .map((c) => conditionToSql(c, table))
        .filter(Boolean) as SQL[]
      if (sub.length > 0) parts.push(not(or(...sub) as SQL) as SQL)
    } else {
      // Regular field — look up the matching Drizzle column on the table.
      const col = (table as Record<string, unknown>)[key]
      if (col === undefined) continue  // unknown column → skip
      const clause = fieldToSql(col, value)
      if (clause) parts.push(clause)
    }
  }

  if (parts.length === 0) return undefined
  if (parts.length === 1) return parts[0]
  return and(...parts) as SQL
}

/**
 * Low-level building block: converts a single serialized ABAC condition
 * object into a Drizzle SQL expression.
 *
 * Field names in the condition must match column property names on the table.
 * Returns `undefined` if the condition is empty or has no recognizable fields.
 *
 * @example
 * ```ts
 * import { toDrizzle } from 'permzplus/adapters/drizzle'
 *
 * const clause = toDrizzle({ status: 'published', views: { $gte: 10 } }, postsTable)
 * // → and(eq(postsTable.status, 'published'), gte(postsTable.views, 10))
 *
 * const posts = await db.select().from(postsTable).where(clause)
 * ```
 */
export function toDrizzle<TTable extends Record<string, unknown>>(
  condition: SubjectConditionObject,
  table: TTable,
): SQL | undefined {
  return conditionToSql(condition, table)
}

/**
 * High-level adapter: resolves the ABAC conditions for a role + permission
 * from the policy engine and returns a Drizzle SQL filter for `.where()`.
 *
 * Field names in the conditions must match column property names on `table`.
 *
 * The conversion is synchronous and happens entirely in-memory — well under 1 ms.
 *
 * @example
 * ```ts
 * import { PolicyEngine } from 'permzplus'
 * import { drizzleFilter } from 'permzplus/adapters/drizzle'
 * import { postsTable } from './schema'
 *
 * const policy = new PolicyEngine()
 * policy.addRole({ name: 'MEMBER', level: 1, permissions: ['posts:read'] })
 * policy.defineRule('MEMBER', 'posts:read', { status: 'published' })
 *
 * const { filter, permitted } = drizzleFilter(policy, 'MEMBER', 'posts:read', postsTable)
 * if (!permitted) return []  // short-circuit — no DB call needed
 *
 * const posts = await db.select().from(postsTable).where(filter)
 * ```
 *
 * @param policy     A `PolicyEngine` (or any object with `can` + `getConditionsFor`).
 * @param role       Role name (e.g. `'MEMBER'`).
 * @param permission Full permission string (e.g. `'posts:read'`).
 * @param table      Drizzle table object whose column names match condition fields.
 */
export function drizzleFilter<TTable extends Record<string, unknown>>(
  policy: QueryEngine,
  role: string,
  permission: string,
  table: TTable,
): DrizzleFilterResult {
  const { permitted, unrestricted, conditions } = accessibleBy(policy, role, permission)

  // Role has no permission at all → block everything.
  if (!permitted) {
    return { permitted: false, unrestricted: false, filter: sql`1 = 0` as SQL }
  }

  // Permitted with no conditions → unrestricted access, no WHERE clause.
  if (unrestricted || conditions.length === 0) {
    return { permitted: true, unrestricted: true, filter: undefined }
  }

  // Convert each condition object to a Drizzle SQL expression.
  // Multiple conditions are OR-combined (any matching condition grants access).
  const sqls: SQL[] = []
  for (let i = 0; i < conditions.length; i++) {
    const clause = conditionToSql(conditions[i], table)
    if (clause) sqls.push(clause)
  }

  if (sqls.length === 0) {
    // All conditions had unrecognized fields — treat as unrestricted to avoid
    // accidentally blocking legitimate access.
    return { permitted: true, unrestricted: true, filter: undefined }
  }

  const filter = sqls.length === 1 ? sqls[0] : (or(...sqls) as SQL)
  return { permitted: true, unrestricted: false, filter }
}
