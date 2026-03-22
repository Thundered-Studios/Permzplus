import type { PermzAdapter, RoleDefinition } from '../types'
import { AdapterError } from '../errors'

/**
 * Schema shape for a PermzRole document stored in the `permzroles` collection.
 *
 * @property name        - Unique role name (e.g. "admin", "editor").
 * @property level       - Numeric hierarchy level; higher values represent more
 *                         privileged roles.
 * @property permissions - Embedded array of permission strings granted to this
 *                         role. Stored directly on the document — no separate
 *                         collection required.
 */
interface PermzRoleDocument {
  name: string
  level: number
  permissions: string[]
}

/**
 * Mongoose adapter for the Permzplus permissions library.
 *
 * Manages a single `permzroles` collection via an embedded schema. Receives
 * either a Mongoose `Connection` instance or the Mongoose singleton as its
 * sole constructor argument. Because Mongoose is an optional peer dependency
 * the parameter type is `unknown` and is cast to `any` internally wherever
 * Mongoose APIs are called.
 *
 * @example
 * ```ts
 * import mongoose from 'mongoose'
 * import { MongooseAdapter } from 'permzplus/adapters/mongoose'
 *
 * await mongoose.connect(process.env.MONGO_URI!)
 * const adapter = new MongooseAdapter(mongoose)
 * ```
 */
export class MongooseAdapter implements PermzAdapter {
  constructor(private mongoose: unknown) {}

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /**
   * Returns the Mongoose `Model` for the `PermzRole` document type.
   *
   * Guards against re-registration — Mongoose throws if you call
   * `mongoose.model()` with the same name twice, so we check
   * `mongoose.models.PermzRole` first and return the cached model when it
   * already exists.
   */
  private getModel() {
    const mg = this.mongoose as any

    if (mg.models.PermzRole) {
      return mg.models.PermzRole
    }

    const schema = new mg.Schema(
      {
        name: { type: String, required: true, unique: true },
        level: { type: Number, required: true },
        permissions: [String],
      },
      { collection: 'permzroles' },
    )

    return mg.model('PermzRole', schema)
  }

  // ---------------------------------------------------------------------------
  // PermzAdapter implementation
  // ---------------------------------------------------------------------------

  /**
   * Retrieves every role stored in the database.
   *
   * @returns A promise that resolves to an array of {@link RoleDefinition}
   *          objects, one per document in the `permzroles` collection.
   * @throws {AdapterError} When the database query fails.
   */
  async getRoles(): Promise<RoleDefinition[]> {
    try {
      const Model = this.getModel()
      const docs: PermzRoleDocument[] = await Model.find({})
      return docs.map((doc) => ({
        name: doc.name,
        level: doc.level,
        permissions: doc.permissions,
      }))
    } catch (err) {
      throw new AdapterError(
        `MongooseAdapter.getRoles failed: ${(err as Error).message}`,
      )
    }
  }

  /**
   * Returns the list of permissions currently granted to the given role.
   *
   * @param role - The role name to look up.
   * @returns A promise that resolves to an array of permission strings, or an
   *          empty array when the role does not exist.
   * @throws {AdapterError} When the database query fails.
   */
  async getPermissions(role: string): Promise<string[]> {
    try {
      const Model = this.getModel()
      const doc: PermzRoleDocument | null = await Model.findOne({ name: role })
      return doc?.permissions ?? []
    } catch (err) {
      throw new AdapterError(
        `MongooseAdapter.getPermissions failed: ${(err as Error).message}`,
      )
    }
  }

  /**
   * Creates or updates a role's `name` and `level` fields.
   *
   * Uses an upsert so the call is idempotent — if no document with the given
   * name exists it is created; otherwise only `name` and `level` are updated.
   * The `permissions` array is intentionally **not** overwritten here; use
   * {@link grantPermission} and {@link revokePermission} to manage permissions.
   *
   * @param role - The role definition to persist.
   * @throws {AdapterError} When the database operation fails.
   */
  async saveRole(role: RoleDefinition): Promise<void> {
    try {
      const Model = this.getModel()
      await Model.findOneAndUpdate(
        { name: role.name },
        { name: role.name, level: role.level },
        { upsert: true, new: true },
      )
    } catch (err) {
      throw new AdapterError(
        `MongooseAdapter.saveRole failed: ${(err as Error).message}`,
      )
    }
  }

  /**
   * Permanently removes a role document from the database.
   *
   * @param role - The name of the role to delete.
   * @throws {AdapterError} When the database operation fails.
   */
  async deleteRole(role: string): Promise<void> {
    try {
      const Model = this.getModel()
      await Model.deleteOne({ name: role })
    } catch (err) {
      throw new AdapterError(
        `MongooseAdapter.deleteRole failed: ${(err as Error).message}`,
      )
    }
  }

  /**
   * Adds a permission to a role's `permissions` array.
   *
   * Uses MongoDB's `$addToSet` operator so that duplicate permissions are
   * silently ignored — the permission string is only stored once regardless of
   * how many times this method is called.
   *
   * @param role       - The name of the role to update.
   * @param permission - The permission string to grant.
   * @throws {AdapterError} When the database operation fails.
   */
  async grantPermission(role: string, permission: string): Promise<void> {
    try {
      const Model = this.getModel()
      await Model.updateOne(
        { name: role },
        { $addToSet: { permissions: permission } },
      )
    } catch (err) {
      throw new AdapterError(
        `MongooseAdapter.grantPermission failed: ${(err as Error).message}`,
      )
    }
  }

  /**
   * Removes a permission from a role's `permissions` array.
   *
   * Uses MongoDB's `$pull` operator to remove all occurrences of the given
   * permission string. If the permission is not present the operation is a
   * no-op.
   *
   * @param role       - The name of the role to update.
   * @param permission - The permission string to revoke.
   * @throws {AdapterError} When the database operation fails.
   */
  async revokePermission(role: string, permission: string): Promise<void> {
    try {
      const Model = this.getModel()
      await Model.updateOne(
        { name: role },
        { $pull: { permissions: permission } },
      )
    } catch (err) {
      throw new AdapterError(
        `MongooseAdapter.revokePermission failed: ${(err as Error).message}`,
      )
    }
  }
}
