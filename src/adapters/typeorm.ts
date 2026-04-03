/**
 * TypeORM adapter for PermzPlus.
 *
 * Works with any database TypeORM supports: PostgreSQL, MySQL, MariaDB,
 * SQLite, MS SQL Server, Oracle, CockroachDB.
 *
 * Define these two entities in your project and pass the `DataSource` or
 * `EntityManager`:
 *
 * ```ts
 * // entities/PermzRole.ts
 * import { Entity, PrimaryColumn, Column } from 'typeorm'
 *
 * @Entity('permzplus_roles')
 * export class PermzRole {
 *   @PrimaryColumn() name: string
 *   @Column('int') level: number
 *   @Column('simple-array') permissions: string[]
 *   @Column('simple-array', { nullable: true }) deniedPermissions: string[]
 * }
 *
 * // entities/PermzUserRole.ts
 * import { Entity, PrimaryColumn, Column, Index } from 'typeorm'
 *
 * @Entity('permzplus_user_roles')
 * @Index(['userId'])
 * export class PermzUserRole {
 *   @PrimaryColumn() userId: string
 *   @PrimaryColumn() roleName: string
 *   @PrimaryColumn({ nullable: true }) tenantId: string
 * }
 * ```
 *
 * @example
 * ```ts
 * import { DataSource } from 'typeorm'
 * import { PolicyEngine } from 'permzplus'
 * import { TypeORMAdapter } from 'permzplus/adapters/typeorm'
 * import { PermzRole, PermzUserRole } from './entities'
 *
 * const ds = new DataSource({ type: 'postgres', entities: [PermzRole, PermzUserRole], ... })
 * await ds.initialize()
 * const adapter = new TypeORMAdapter(ds)
 * const policy = await PolicyEngine.fromAdapter(adapter)
 * ```
 */

import type { PermzAdapter, RoleDefinition } from '../types'

// ---------------------------------------------------------------------------
// Minimal TypeORM type shim
// ---------------------------------------------------------------------------

interface TypeORMRepository<T> {
  find(options?: { where?: Record<string, unknown> }): Promise<T[]>
  findOne(options: { where: Record<string, unknown> }): Promise<T | null>
  save(entity: Partial<T>): Promise<T>
  delete(criteria: Record<string, unknown>): Promise<unknown>
}

interface TypeORMDataSource {
  getRepository<T>(entity: new () => T): TypeORMRepository<T>
}

// Minimal entity shapes — users pass their own entity classes
interface RoleEntity {
  name: string
  level: number
  permissions: string[]
  deniedPermissions: string[]
}

interface UserRoleEntity {
  userId: string
  roleName: string
  tenantId: string | null
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface TypeORMAdapterOptions<R extends RoleEntity, U extends UserRoleEntity> {
  /** Your PermzRole entity class. */
  roleEntity: new () => R
  /** Your PermzUserRole entity class. */
  userRoleEntity: new () => U
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

export class TypeORMAdapter<
  R extends RoleEntity = RoleEntity,
  U extends UserRoleEntity = UserRoleEntity,
> implements PermzAdapter {
  private ds: TypeORMDataSource
  private RoleEntity: new () => R
  private UserRoleEntity: new () => U

  constructor(dataSource: TypeORMDataSource, options: TypeORMAdapterOptions<R, U>) {
    this.ds = dataSource
    this.RoleEntity = options.roleEntity
    this.UserRoleEntity = options.userRoleEntity
  }

  private roles(): TypeORMRepository<R> { return this.ds.getRepository(this.RoleEntity) }
  private userRoles(): TypeORMRepository<U> { return this.ds.getRepository(this.UserRoleEntity) }

  private parseArray(value: string[] | null | undefined): string[] {
    if (!value) return []
    // TypeORM simple-array stores as comma-separated string sometimes
    if (typeof value === 'string') return (value as string).split(',').map((s) => s.trim()).filter(Boolean)
    return value
  }

  async getRoles(): Promise<RoleDefinition[]> {
    const rows = await this.roles().find()
    return rows.map((r) => ({
      name: r.name,
      level: r.level,
      permissions: this.parseArray(r.permissions),
    }))
  }

  async getPermissions(role: string): Promise<string[]> {
    const row = await this.roles().findOne({ where: { name: role } as Record<string, unknown> })
    return this.parseArray(row?.permissions)
  }

  async saveRole(role: RoleDefinition): Promise<void> {
    await this.roles().save({ name: role.name, level: role.level, permissions: role.permissions } as Partial<R>)
  }

  async deleteRole(role: string): Promise<void> {
    await this.roles().delete({ name: role })
  }

  async grantPermission(role: string, permission: string): Promise<void> {
    const current = await this.getPermissions(role)
    if (current.includes(permission)) return
    await this.roles().save({ name: role, permissions: [...current, permission] } as Partial<R>)
  }

  async revokePermission(role: string, permission: string): Promise<void> {
    const current = await this.getPermissions(role)
    await this.roles().save({ name: role, permissions: current.filter((p) => p !== permission) } as Partial<R>)
  }

  async getDeniedPermissions(role: string): Promise<string[]> {
    const row = await this.roles().findOne({ where: { name: role } as Record<string, unknown> })
    return this.parseArray(row?.deniedPermissions)
  }

  async saveDeny(role: string, permission: string): Promise<void> {
    const current = await this.getDeniedPermissions(role)
    if (current.includes(permission)) return
    await this.roles().save({ name: role, deniedPermissions: [...current, permission] } as Partial<R>)
  }

  async removeDeny(role: string, permission: string): Promise<void> {
    const current = await this.getDeniedPermissions(role)
    await this.roles().save({ name: role, deniedPermissions: current.filter((p) => p !== permission) } as Partial<R>)
  }

  async assignRole(userId: string, roleName: string, tenantId?: string): Promise<void> {
    const existing = await this.userRoles().findOne({
      where: { userId, roleName, tenantId: tenantId ?? null } as Record<string, unknown>,
    })
    if (existing) return
    await this.userRoles().save({ userId, roleName, tenantId: tenantId ?? null } as Partial<U>)
  }

  async revokeRole(userId: string, roleName: string, tenantId?: string): Promise<void> {
    await this.userRoles().delete({ userId, roleName, tenantId: tenantId ?? null })
  }

  async getUserRoles(userId: string, tenantId?: string): Promise<string[]> {
    const rows = await this.userRoles().find({
      where: { userId, tenantId: tenantId ?? null } as Record<string, unknown>,
    })
    return rows.map((r) => r.roleName)
  }
}
