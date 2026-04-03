/**
 * Sequelize adapter for PermzPlus.
 *
 * Works with PostgreSQL, MySQL, MariaDB, SQLite, MS SQL Server.
 *
 * Define and sync these two models, then pass them to `SequelizeAdapter`:
 *
 * ```ts
 * import { DataTypes, Model, Sequelize } from 'sequelize'
 *
 * export class PermzRole extends Model {
 *   declare name: string
 *   declare level: number
 *   declare permissions: string[]
 *   declare deniedPermissions: string[]
 * }
 * PermzRole.init({
 *   name:               { type: DataTypes.STRING, primaryKey: true },
 *   level:              { type: DataTypes.INTEGER, defaultValue: 1 },
 *   permissions:        { type: DataTypes.JSON,   defaultValue: [] },
 *   deniedPermissions:  { type: DataTypes.JSON,   defaultValue: [] },
 * }, { sequelize, tableName: 'permzplus_roles', timestamps: false })
 *
 * export class PermzUserRole extends Model {
 *   declare userId: string
 *   declare roleName: string
 *   declare tenantId: string | null
 * }
 * PermzUserRole.init({
 *   userId:   { type: DataTypes.STRING, primaryKey: true },
 *   roleName: { type: DataTypes.STRING, primaryKey: true },
 *   tenantId: { type: DataTypes.STRING, primaryKey: true, allowNull: true },
 * }, { sequelize, tableName: 'permzplus_user_roles', timestamps: false })
 * ```
 *
 * @example
 * ```ts
 * import { PolicyEngine } from 'permzplus'
 * import { SequelizeAdapter } from 'permzplus/adapters/sequelize'
 * import { PermzRole, PermzUserRole } from './models'
 *
 * const adapter = new SequelizeAdapter({ roleModel: PermzRole, userRoleModel: PermzUserRole })
 * const policy = await PolicyEngine.fromAdapter(adapter)
 * ```
 */

import type { PermzAdapter, RoleDefinition } from '../types'

// ---------------------------------------------------------------------------
// Minimal Sequelize model type shim
// ---------------------------------------------------------------------------

interface FindOptions {
  where?: Record<string, unknown>
}

interface SequelizeModel<T> {
  findAll(options?: FindOptions): Promise<T[]>
  findOne(options: FindOptions): Promise<T | null>
  upsert(values: Partial<T>): Promise<unknown>
  update(values: Partial<T>, options: { where: Record<string, unknown> }): Promise<unknown>
  destroy(options: { where: Record<string, unknown> }): Promise<unknown>
  create(values: Partial<T>): Promise<T>
}

interface RoleRow {
  name: string
  level: number
  permissions: string[]
  deniedPermissions: string[]
}

interface UserRoleRow {
  userId: string
  roleName: string
  tenantId: string | null
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface SequelizeAdapterOptions {
  roleModel: SequelizeModel<RoleRow>
  userRoleModel: SequelizeModel<UserRoleRow>
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

export class SequelizeAdapter implements PermzAdapter {
  private roleModel: SequelizeModel<RoleRow>
  private userRoleModel: SequelizeModel<UserRoleRow>

  constructor(options: SequelizeAdapterOptions) {
    this.roleModel = options.roleModel
    this.userRoleModel = options.userRoleModel
  }

  private ensureArray(value: string[] | string | null | undefined): string[] {
    if (!value) return []
    if (Array.isArray(value)) return value
    try { return JSON.parse(value as string) as string[] } catch { return [] }
  }

  async getRoles(): Promise<RoleDefinition[]> {
    const rows = await this.roleModel.findAll()
    return rows.map((r) => ({
      name: r.name,
      level: r.level,
      permissions: this.ensureArray(r.permissions),
    }))
  }

  async getPermissions(role: string): Promise<string[]> {
    const row = await this.roleModel.findOne({ where: { name: role } })
    return this.ensureArray(row?.permissions)
  }

  async saveRole(role: RoleDefinition): Promise<void> {
    await this.roleModel.upsert({ name: role.name, level: role.level, permissions: role.permissions })
  }

  async deleteRole(role: string): Promise<void> {
    await this.roleModel.destroy({ where: { name: role } })
  }

  async grantPermission(role: string, permission: string): Promise<void> {
    const current = await this.getPermissions(role)
    if (current.includes(permission)) return
    await this.roleModel.update({ permissions: [...current, permission] }, { where: { name: role } })
  }

  async revokePermission(role: string, permission: string): Promise<void> {
    const current = await this.getPermissions(role)
    await this.roleModel.update({ permissions: current.filter((p) => p !== permission) }, { where: { name: role } })
  }

  async getDeniedPermissions(role: string): Promise<string[]> {
    const row = await this.roleModel.findOne({ where: { name: role } })
    return this.ensureArray(row?.deniedPermissions)
  }

  async saveDeny(role: string, permission: string): Promise<void> {
    const current = await this.getDeniedPermissions(role)
    if (current.includes(permission)) return
    await this.roleModel.update({ deniedPermissions: [...current, permission] }, { where: { name: role } })
  }

  async removeDeny(role: string, permission: string): Promise<void> {
    const current = await this.getDeniedPermissions(role)
    await this.roleModel.update({ deniedPermissions: current.filter((p) => p !== permission) }, { where: { name: role } })
  }

  async assignRole(userId: string, roleName: string, tenantId?: string): Promise<void> {
    const existing = await this.userRoleModel.findOne({ where: { userId, roleName, tenantId: tenantId ?? null } })
    if (existing) return
    await this.userRoleModel.create({ userId, roleName, tenantId: tenantId ?? null })
  }

  async revokeRole(userId: string, roleName: string, tenantId?: string): Promise<void> {
    await this.userRoleModel.destroy({ where: { userId, roleName, tenantId: tenantId ?? null } })
  }

  async getUserRoles(userId: string, tenantId?: string): Promise<string[]> {
    const rows = await this.userRoleModel.findAll({ where: { userId, tenantId: tenantId ?? null } })
    return rows.map((r) => r.roleName)
  }
}
