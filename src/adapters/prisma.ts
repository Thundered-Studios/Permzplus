import type { PermzAdapter, RoleDefinition } from '../types'
import { AdapterError } from '../errors'

/**
 * Prisma adapter for Permzplus.
 *
 * Persists roles and permissions using a PrismaClient instance provided by the
 * consumer. Because `@prisma/client` is an optional peer dependency its types
 * are not imported directly; the constructor accepts `unknown` and the client
 * is cast internally.
 *
 * The consumer's Prisma schema must include the following two models:
 *
 * ```prisma
 * model PermzRole {
 *   name        String            @id
 *   level       Int
 *   permissions PermzPermission[]
 * }
 *
 * model PermzPermission {
 *   id         Int       @id @default(autoincrement())
 *   roleName   String
 *   permission String
 *   role       PermzRole @relation(fields: [roleName], references: [name], onDelete: Cascade)
 *
 *   @@unique([roleName, permission])
 * }
 * ```
 */
export class PrismaAdapter implements PermzAdapter {
  private readonly prisma: unknown

  constructor(prisma: unknown) {
    this.prisma = prisma
  }

  // ---------------------------------------------------------------------------
  // Internal helpers
  // ---------------------------------------------------------------------------

  /** Typed accessor for the `permzRole` Prisma model delegate. */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private get roleDelegate(): any {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return (this.prisma as any).permzRole
  }

  /** Typed accessor for the `permzPermission` Prisma model delegate. */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private get permissionDelegate(): any {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return (this.prisma as any).permzPermission
  }

  // ---------------------------------------------------------------------------
  // PermzAdapter implementation
  // ---------------------------------------------------------------------------

  /**
   * Retrieves all roles together with their associated permissions.
   *
   * @returns An array of {@link RoleDefinition} objects, each containing the
   *   role name, numeric level, and the list of permission strings granted to
   *   that role.
   */
  async getRoles(): Promise<RoleDefinition[]> {
    try {
      const records = await this.roleDelegate.findMany({
        include: { permissions: true },
      })

      return records.map((record: any) => ({
        name: record.name,
        level: record.level,
        permissions: record.permissions.map((p: any) => p.permission as string),
      }))
    } catch (err) {
      throw new AdapterError(
        `PrismaAdapter.getRoles failed: ${(err as Error).message ?? err}`,
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
      const records = await this.permissionDelegate.findMany({
        where: { roleName: role },
      })

      return records.map((r: any) => r.permission as string)
    } catch (err) {
      throw new AdapterError(
        `PrismaAdapter.getPermissions failed for role "${role}": ${(err as Error).message ?? err}`,
      )
    }
  }

  /**
   * Creates or updates a role record in the database.
   *
   * Only the role name and level are persisted here. Permissions are managed
   * separately via {@link grantPermission} and {@link revokePermission}.
   *
   * @param role - The {@link RoleDefinition} to upsert.
   */
  async saveRole(role: RoleDefinition): Promise<void> {
    try {
      await this.roleDelegate.upsert({
        where: { name: role.name },
        create: { name: role.name, level: role.level },
        update: { level: role.level },
      })
    } catch (err) {
      throw new AdapterError(
        `PrismaAdapter.saveRole failed for role "${role.name}": ${(err as Error).message ?? err}`,
      )
    }
  }

  /**
   * Deletes a role from the database.
   *
   * Associated `PermzPermission` rows are removed automatically via the
   * `onDelete: Cascade` relation defined in the schema.
   *
   * @param role - The name of the role to delete.
   */
  async deleteRole(role: string): Promise<void> {
    try {
      await this.roleDelegate.delete({
        where: { name: role },
      })
    } catch (err) {
      throw new AdapterError(
        `PrismaAdapter.deleteRole failed for role "${role}": ${(err as Error).message ?? err}`,
      )
    }
  }

  /**
   * Grants a permission to a role, creating the record if it does not already
   * exist. If the `(roleName, permission)` pair is already present the
   * operation is a no-op (the `update` clause is intentionally empty).
   *
   * @param role - The name of the role to grant the permission to.
   * @param permission - The permission string to grant.
   */
  async grantPermission(role: string, permission: string): Promise<void> {
    try {
      await this.permissionDelegate.upsert({
        where: { roleName_permission: { roleName: role, permission } },
        create: { roleName: role, permission },
        update: {},
      })
    } catch (err) {
      throw new AdapterError(
        `PrismaAdapter.grantPermission failed for role "${role}", permission "${permission}": ${(err as Error).message ?? err}`,
      )
    }
  }

  /**
   * Revokes a permission from a role.
   *
   * Uses `deleteMany` so that the operation is a no-op when the record does
   * not exist, rather than throwing a Prisma `RecordNotFound` error.
   *
   * @param role - The name of the role to revoke the permission from.
   * @param permission - The permission string to revoke.
   */
  async revokePermission(role: string, permission: string): Promise<void> {
    try {
      await this.permissionDelegate.deleteMany({
        where: { roleName: role, permission },
      })
    } catch (err) {
      throw new AdapterError(
        `PrismaAdapter.revokePermission failed for role "${role}", permission "${permission}": ${(err as Error).message ?? err}`,
      )
    }
  }
}
