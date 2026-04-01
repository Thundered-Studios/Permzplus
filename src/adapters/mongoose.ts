import type { PermzAdapter, RoleDefinition } from '../types'
import { AdapterError } from '../errors'

interface PermzRoleDocument {
  name: string
  level: number
  permissions: string[]
  deniedPermissions: string[]
}

interface PermzUserRoleDocument {
  userId: string
  roleName: string
  tenantId: string
}

/**
 * Mongoose adapter for Permzplus.
 *
 * Manages a `permzroles` collection for role definitions and a `permzuserroles`
 * collection for user-role assignments. Receives either a Mongoose `Connection`
 * instance or the Mongoose singleton as its sole constructor argument.
 *
 * @example
 * ```ts
 * import mongoose from 'mongoose'
 * import { MongooseAdapter } from 'permzplus/adapters/mongoose'
 *
 * await mongoose.connect(process.env.MONGO_URI!)
 * const adapter = new MongooseAdapter(mongoose)
 * const policy = await PolicyEngine.fromAdapter(adapter)
 * ```
 */
export class MongooseAdapter implements PermzAdapter {
  constructor(private mongoose: unknown) {}

  // ---------------------------------------------------------------------------
  // Private model helpers
  // ---------------------------------------------------------------------------

  private getRoleModel() {
    const mg = this.mongoose as any
    if (mg.models.PermzRole) return mg.models.PermzRole

    const schema = new mg.Schema(
      {
        name: { type: String, required: true, unique: true },
        level: { type: Number, required: true },
        permissions: [String],
        deniedPermissions: [String],
      },
      { collection: 'permzroles' },
    )
    return mg.model('PermzRole', schema)
  }

  private getUserRoleModel() {
    const mg = this.mongoose as any
    if (mg.models.PermzUserRole) return mg.models.PermzUserRole

    const schema = new mg.Schema(
      {
        userId: { type: String, required: true },
        roleName: { type: String, required: true },
        tenantId: { type: String, default: '' },
      },
      { collection: 'permzuserroles' },
    )
    schema.index({ userId: 1, tenantId: 1 })
    schema.index({ userId: 1, roleName: 1, tenantId: 1 }, { unique: true })
    return mg.model('PermzUserRole', schema)
  }

  // ---------------------------------------------------------------------------
  // Role definition methods
  // ---------------------------------------------------------------------------

  async getRoles(): Promise<RoleDefinition[]> {
    try {
      const Model = this.getRoleModel()
      const docs: PermzRoleDocument[] = await Model.find({})
      return docs.map((doc) => ({
        name: doc.name,
        level: doc.level,
        permissions: doc.permissions,
      }))
    } catch (err) {
      throw new AdapterError(`MongooseAdapter.getRoles failed: ${(err as Error).message}`)
    }
  }

  async getPermissions(role: string): Promise<string[]> {
    try {
      const Model = this.getRoleModel()
      const doc: PermzRoleDocument | null = await Model.findOne({ name: role })
      return doc?.permissions ?? []
    } catch (err) {
      throw new AdapterError(`MongooseAdapter.getPermissions failed: ${(err as Error).message}`)
    }
  }

  async saveRole(role: RoleDefinition): Promise<void> {
    try {
      const Model = this.getRoleModel()
      await Model.findOneAndUpdate(
        { name: role.name },
        { name: role.name, level: role.level },
        { upsert: true, new: true },
      )
    } catch (err) {
      throw new AdapterError(`MongooseAdapter.saveRole failed: ${(err as Error).message}`)
    }
  }

  async deleteRole(role: string): Promise<void> {
    try {
      const Model = this.getRoleModel()
      await Model.deleteOne({ name: role })
    } catch (err) {
      throw new AdapterError(`MongooseAdapter.deleteRole failed: ${(err as Error).message}`)
    }
  }

  async grantPermission(role: string, permission: string): Promise<void> {
    try {
      const Model = this.getRoleModel()
      await Model.updateOne({ name: role }, { $addToSet: { permissions: permission } })
    } catch (err) {
      throw new AdapterError(`MongooseAdapter.grantPermission failed: ${(err as Error).message}`)
    }
  }

  async revokePermission(role: string, permission: string): Promise<void> {
    try {
      const Model = this.getRoleModel()
      await Model.updateOne({ name: role }, { $pull: { permissions: permission } })
    } catch (err) {
      throw new AdapterError(`MongooseAdapter.revokePermission failed: ${(err as Error).message}`)
    }
  }

  async getDeniedPermissions(role: string): Promise<string[]> {
    try {
      const Model = this.getRoleModel()
      const doc: PermzRoleDocument | null = await Model.findOne({ name: role })
      return doc?.deniedPermissions ?? []
    } catch (err) {
      throw new AdapterError(
        `MongooseAdapter.getDeniedPermissions failed: ${(err as Error).message}`,
      )
    }
  }

  async saveDeny(role: string, permission: string): Promise<void> {
    try {
      const Model = this.getRoleModel()
      await Model.updateOne({ name: role }, { $addToSet: { deniedPermissions: permission } })
    } catch (err) {
      throw new AdapterError(`MongooseAdapter.saveDeny failed: ${(err as Error).message}`)
    }
  }

  async removeDeny(role: string, permission: string): Promise<void> {
    try {
      const Model = this.getRoleModel()
      await Model.updateOne({ name: role }, { $pull: { deniedPermissions: permission } })
    } catch (err) {
      throw new AdapterError(`MongooseAdapter.removeDeny failed: ${(err as Error).message}`)
    }
  }

  // ---------------------------------------------------------------------------
  // User-role assignment methods
  // ---------------------------------------------------------------------------

  /**
   * Assigns a role to a user. Uses `updateOne` with `upsert: true` so duplicate
   * assignments are a no-op.
   */
  async assignRole(userId: string, roleName: string, tenantId = ''): Promise<void> {
    try {
      const Model = this.getUserRoleModel()
      await Model.updateOne(
        { userId, roleName, tenantId },
        { userId, roleName, tenantId },
        { upsert: true },
      )
    } catch (err) {
      throw new AdapterError(
        `MongooseAdapter.assignRole failed for user "${userId}", role "${roleName}": ${(err as Error).message}`,
      )
    }
  }

  /** Revokes a role from a user. No-op if the assignment does not exist. */
  async revokeRole(userId: string, roleName: string, tenantId = ''): Promise<void> {
    try {
      const Model = this.getUserRoleModel()
      await Model.deleteOne({ userId, roleName, tenantId })
    } catch (err) {
      throw new AdapterError(
        `MongooseAdapter.revokeRole failed for user "${userId}", role "${roleName}": ${(err as Error).message}`,
      )
    }
  }

  /** Returns all role names assigned to a user, optionally filtered by tenant. */
  async getUserRoles(userId: string, tenantId = ''): Promise<string[]> {
    try {
      const Model = this.getUserRoleModel()
      const docs: PermzUserRoleDocument[] = await Model.find({ userId, tenantId })
      return docs.map((d) => d.roleName)
    } catch (err) {
      throw new AdapterError(
        `MongooseAdapter.getUserRoles failed for user "${userId}": ${(err as Error).message}`,
      )
    }
  }
}
