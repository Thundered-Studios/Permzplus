/**
 * Knex adapter for PermzPlus.
 *
 * Works with any SQL database Knex supports: PostgreSQL, MySQL, MariaDB,
 * SQLite3, MS SQL Server, Oracle, Amazon Redshift.
 *
 * Run this migration to create the required tables:
 *
 * ```ts
 * await knex.schema.createTableIfNotExists('permzplus_roles', (t) => {
 *   t.string('name').primary()
 *   t.integer('level').notNullable().defaultTo(1)
 *   t.text('permissions').notNullable().defaultTo('[]')       // JSON array
 *   t.text('denied_permissions').notNullable().defaultTo('[]') // JSON array
 * })
 *
 * await knex.schema.createTableIfNotExists('permzplus_user_roles', (t) => {
 *   t.string('user_id').notNullable()
 *   t.string('role_name').notNullable().references('name').inTable('permzplus_roles').onDelete('CASCADE')
 *   t.string('tenant_id').nullable()
 *   t.primary(['user_id', 'role_name', 'tenant_id'])
 *   t.index('user_id')
 * })
 * ```
 *
 * @example
 * ```ts
 * import knex from 'knex'
 * import { PolicyEngine } from 'permzplus'
 * import { KnexAdapter } from 'permzplus/adapters/knex'
 *
 * const db = knex({ client: 'pg', connection: process.env.DATABASE_URL })
 * const adapter = new KnexAdapter(db)
 * const policy = await PolicyEngine.fromAdapter(adapter)
 * ```
 */

import type { PermzAdapter, RoleDefinition } from '../types'

// ---------------------------------------------------------------------------
// Minimal Knex type shim
// ---------------------------------------------------------------------------

interface KnexQueryBuilder<T = Record<string, unknown>> {
  select(...cols: string[]): KnexQueryBuilder<T>
  where(col: string, value: unknown): KnexQueryBuilder<T>
  whereNull(col: string): KnexQueryBuilder<T>
  insert(data: Record<string, unknown>): Promise<unknown>
  update(data: Record<string, unknown>): Promise<unknown>
  delete(): Promise<unknown>
  first(): Promise<T | undefined>
  then: Promise<T[]>['then']
}

interface KnexInstance {
  (table: string): KnexQueryBuilder
  schema: {
    createTableIfNotExists(name: string, cb: (t: unknown) => void): Promise<void>
  }
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface KnexAdapterOptions {
  /** Table for role definitions. @default "permzplus_roles" */
  rolesTable?: string
  /** Table for user-role assignments. @default "permzplus_user_roles" */
  userRolesTable?: string
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

export class KnexAdapter implements PermzAdapter {
  private db: KnexInstance
  private rolesTable: string
  private userRolesTable: string

  constructor(db: KnexInstance, options?: KnexAdapterOptions) {
    this.db = db
    this.rolesTable = options?.rolesTable ?? 'permzplus_roles'
    this.userRolesTable = options?.userRolesTable ?? 'permzplus_user_roles'
  }

  private parseJson(value: string | string[] | null | undefined): string[] {
    if (!value) return []
    if (Array.isArray(value)) return value
    try { return JSON.parse(value) as string[] } catch { return [] }
  }

  async getRoles(): Promise<RoleDefinition[]> {
    const rows = await (this.db(this.rolesTable).select('name', 'level', 'permissions') as unknown as Promise<Record<string, unknown>[]>)
    return rows.map((r) => ({
      name: String(r.name),
      level: Number(r.level ?? 1),
      permissions: this.parseJson(r.permissions as string),
    }))
  }

  async getPermissions(role: string): Promise<string[]> {
    const row = await this.db(this.rolesTable).select('permissions').where('name', role).first() as Record<string, unknown> | undefined
    return this.parseJson(row?.permissions as string)
  }

  async saveRole(role: RoleDefinition): Promise<void> {
    const existing = await this.db(this.rolesTable).where('name', role.name).first()
    const data = { name: role.name, level: role.level, permissions: JSON.stringify(role.permissions) }
    if (existing) {
      await this.db(this.rolesTable).where('name', role.name).update(data)
    } else {
      await this.db(this.rolesTable).insert(data)
    }
  }

  async deleteRole(role: string): Promise<void> {
    await this.db(this.rolesTable).where('name', role).delete()
  }

  async grantPermission(role: string, permission: string): Promise<void> {
    const current = await this.getPermissions(role)
    if (current.includes(permission)) return
    await this.db(this.rolesTable).where('name', role).update({ permissions: JSON.stringify([...current, permission]) })
  }

  async revokePermission(role: string, permission: string): Promise<void> {
    const current = await this.getPermissions(role)
    await this.db(this.rolesTable).where('name', role).update({ permissions: JSON.stringify(current.filter((p) => p !== permission)) })
  }

  async getDeniedPermissions(role: string): Promise<string[]> {
    const row = await this.db(this.rolesTable).select('denied_permissions').where('name', role).first() as Record<string, unknown> | undefined
    return this.parseJson(row?.denied_permissions as string)
  }

  async saveDeny(role: string, permission: string): Promise<void> {
    const current = await this.getDeniedPermissions(role)
    if (current.includes(permission)) return
    await this.db(this.rolesTable).where('name', role).update({ denied_permissions: JSON.stringify([...current, permission]) })
  }

  async removeDeny(role: string, permission: string): Promise<void> {
    const current = await this.getDeniedPermissions(role)
    await this.db(this.rolesTable).where('name', role).update({ denied_permissions: JSON.stringify(current.filter((p) => p !== permission)) })
  }

  async assignRole(userId: string, roleName: string, tenantId?: string): Promise<void> {
    const q = this.db(this.userRolesTable).where('user_id', userId).where('role_name', roleName)
    const existing = await (tenantId ? q.where('tenant_id', tenantId) : q.whereNull('tenant_id')).first()
    if (existing) return
    await this.db(this.userRolesTable).insert({ user_id: userId, role_name: roleName, tenant_id: tenantId ?? null })
  }

  async revokeRole(userId: string, roleName: string, tenantId?: string): Promise<void> {
    const q = this.db(this.userRolesTable).where('user_id', userId).where('role_name', roleName)
    await (tenantId ? q.where('tenant_id', tenantId) : q.whereNull('tenant_id')).delete()
  }

  async getUserRoles(userId: string, tenantId?: string): Promise<string[]> {
    const q = this.db(this.userRolesTable).select('role_name').where('user_id', userId)
    const rows = await (tenantId ? q.where('tenant_id', tenantId) : q.whereNull('tenant_id')) as unknown as Record<string, unknown>[]
    return rows.map((r) => String(r.role_name))
  }
}
