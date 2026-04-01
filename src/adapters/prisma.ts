import type { PermzAdapter, RoleDefinition } from '../types'
import { AdapterError } from '../errors'

/**
 * Prisma adapter for Permzplus.
 *
 * Persists roles, permissions, and user-role assignments using a PrismaClient
 * instance. Because `@prisma/client` is an optional peer dependency its types
 * are not imported directly; the constructor accepts `unknown` and the client
 * is cast internally.
 *
 * **Required Prisma schema — add these models to your `schema.prisma`:**
 *
 * ```prisma
 * model PermzRole {
 *   name        String            @id
 *   level       Int
 *   permissions PermzPermission[]
 *   denies      PermzDeny[]
 *   userRoles   PermzUserRole[]
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
 *
 * model PermzDeny {
 *   id         Int       @id @default(autoincrement())
 *   roleName   String
 *   permission String
 *   role       PermzRole @relation(fields: [roleName], references: [name], onDelete: Cascade)
 *
 *   @@unique([roleName, permission])
 * }
 *
 * // Required only if you use assignRole() / canUser() / createUserContext()
 * model PermzUserRole {
 *   id       Int       @id @default(autoincrement())
 *   userId   String
 *   roleName String
 *   tenantId String    @default("")
 *   role     PermzRole @relation(fields: [roleName], references: [name], onDelete: Cascade)
 *
 *   @@unique([userId, roleName, tenantId])
 *   @@index([userId, tenantId])
 * }
 * ```
 */
export class PrismaAdapter implements PermzAdapter {
  private readonly prisma: unknown

  constructor(prisma: unknown) {
    this.prisma = prisma
  }

  // ---------------------------------------------------------------------------
  // Internal delegate helpers
  // ---------------------------------------------------------------------------

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private get roleDelegate(): any {
    return (this.prisma as any).permzRole
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private get permissionDelegate(): any {
    return (this.prisma as any).permzPermission
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private get denyDelegate(): any {
    return (this.prisma as any).permzDeny
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private get userRoleDelegate(): any {
    return (this.prisma as any).permzUserRole
  }

  // ---------------------------------------------------------------------------
  // Role definition methods
  // ---------------------------------------------------------------------------

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
      throw new AdapterError(`PrismaAdapter.getRoles failed: ${(err as Error).message ?? err}`)
    }
  }

  async getPermissions(role: string): Promise<string[]> {
    try {
      const records = await this.permissionDelegate.findMany({ where: { roleName: role } })
      return records.map((r: any) => r.permission as string)
    } catch (err) {
      throw new AdapterError(
        `PrismaAdapter.getPermissions failed for role "${role}": ${(err as Error).message ?? err}`,
      )
    }
  }

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

  async deleteRole(role: string): Promise<void> {
    try {
      await this.roleDelegate.delete({ where: { name: role } })
    } catch (err) {
      throw new AdapterError(
        `PrismaAdapter.deleteRole failed for role "${role}": ${(err as Error).message ?? err}`,
      )
    }
  }

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

  async revokePermission(role: string, permission: string): Promise<void> {
    try {
      await this.permissionDelegate.deleteMany({ where: { roleName: role, permission } })
    } catch (err) {
      throw new AdapterError(
        `PrismaAdapter.revokePermission failed for role "${role}", permission "${permission}": ${(err as Error).message ?? err}`,
      )
    }
  }

  async getDeniedPermissions(role: string): Promise<string[]> {
    try {
      const records = await this.denyDelegate.findMany({ where: { roleName: role } })
      return records.map((r: any) => r.permission as string)
    } catch (err) {
      throw new AdapterError(
        `PrismaAdapter.getDeniedPermissions failed for role "${role}": ${(err as Error).message ?? err}`,
      )
    }
  }

  async saveDeny(role: string, permission: string): Promise<void> {
    try {
      await this.denyDelegate.upsert({
        where: { roleName_permission: { roleName: role, permission } },
        create: { roleName: role, permission },
        update: {},
      })
    } catch (err) {
      throw new AdapterError(
        `PrismaAdapter.saveDeny failed for role "${role}", permission "${permission}": ${(err as Error).message ?? err}`,
      )
    }
  }

  async removeDeny(role: string, permission: string): Promise<void> {
    try {
      await this.denyDelegate.deleteMany({ where: { roleName: role, permission } })
    } catch (err) {
      throw new AdapterError(
        `PrismaAdapter.removeDeny failed for role "${role}", permission "${permission}": ${(err as Error).message ?? err}`,
      )
    }
  }

  // ---------------------------------------------------------------------------
  // User-role assignment methods
  // ---------------------------------------------------------------------------

  /**
   * Assigns a role to a user, optionally scoped to a tenant.
   * Uses upsert so the call is idempotent.
   */
  async assignRole(userId: string, roleName: string, tenantId = ''): Promise<void> {
    try {
      await this.userRoleDelegate.upsert({
        where: { userId_roleName_tenantId: { userId, roleName, tenantId } },
        create: { userId, roleName, tenantId },
        update: {},
      })
    } catch (err) {
      throw new AdapterError(
        `PrismaAdapter.assignRole failed for user "${userId}", role "${roleName}": ${(err as Error).message ?? err}`,
      )
    }
  }

  /**
   * Revokes a role from a user. Uses `deleteMany` so it is a no-op when the
   * assignment does not exist.
   */
  async revokeRole(userId: string, roleName: string, tenantId = ''): Promise<void> {
    try {
      await this.userRoleDelegate.deleteMany({ where: { userId, roleName, tenantId } })
    } catch (err) {
      throw new AdapterError(
        `PrismaAdapter.revokeRole failed for user "${userId}", role "${roleName}": ${(err as Error).message ?? err}`,
      )
    }
  }

  /** Returns all role names assigned to a user, optionally filtered by tenant. */
  async getUserRoles(userId: string, tenantId = ''): Promise<string[]> {
    try {
      const records = await this.userRoleDelegate.findMany({ where: { userId, tenantId } })
      return records.map((r: any) => r.roleName as string)
    } catch (err) {
      throw new AdapterError(
        `PrismaAdapter.getUserRoles failed for user "${userId}": ${(err as Error).message ?? err}`,
      )
    }
  }
}
