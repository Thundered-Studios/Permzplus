/**
 * Redis adapter for PermzPlus.
 *
 * Stores role definitions and user-role assignments as Redis hashes and sets.
 * Compatible with both `ioredis` and the official `redis` (node-redis) client —
 * any client that exposes the standard command methods works.
 *
 * Key schema:
 * ```
 * {prefix}:role:{name}          HASH  name, level, permissions (JSON), denied_permissions (JSON)
 * {prefix}:roles                SET   all role names
 * {prefix}:user:{userId}:roles  SET   role names for the user (no tenant)
 * {prefix}:user:{userId}:tenant:{tenantId}:roles  SET  tenant-scoped roles
 * ```
 *
 * @example
 * ```ts
 * // ioredis
 * import Redis from 'ioredis'
 * import { PolicyEngine } from 'permzplus'
 * import { RedisAdapter } from 'permzplus/adapters/redis'
 *
 * const redis = new Redis()
 * const adapter = new RedisAdapter(redis)
 * const policy = await PolicyEngine.fromAdapter(adapter)
 * ```
 *
 * @example
 * ```ts
 * // node-redis
 * import { createClient } from 'redis'
 * const redis = createClient()
 * await redis.connect()
 * const adapter = new RedisAdapter(redis)
 * ```
 */

import type { PermzAdapter, RoleDefinition } from '../types'

// ---------------------------------------------------------------------------
// Minimal Redis client shim (ioredis + node-redis compatible)
// ---------------------------------------------------------------------------

interface RedisClient {
  hset(key: string, ...args: (string | number)[]): Promise<unknown>
  hgetall(key: string): Promise<Record<string, string> | null>
  hdel(key: string, ...fields: string[]): Promise<unknown>
  del(key: string): Promise<unknown>
  sadd(key: string, ...members: string[]): Promise<unknown>
  srem(key: string, ...members: string[]): Promise<unknown>
  smembers(key: string): Promise<string[]>
  exists(key: string): Promise<number>
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface RedisAdapterOptions {
  /** Key prefix for all PermzPlus keys. @default "permzplus" */
  prefix?: string
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

export class RedisAdapter implements PermzAdapter {
  private client: RedisClient
  private prefix: string

  constructor(client: RedisClient, options?: RedisAdapterOptions) {
    this.client = client
    this.prefix = options?.prefix ?? 'permzplus'
  }

  private roleKey(name: string): string { return `${this.prefix}:role:${name}` }
  private rolesSetKey(): string { return `${this.prefix}:roles` }
  private userRolesKey(userId: string, tenantId?: string): string {
    return tenantId
      ? `${this.prefix}:user:${userId}:tenant:${tenantId}:roles`
      : `${this.prefix}:user:${userId}:roles`
  }

  private parseJsonField(value: string | undefined): string[] {
    if (!value) return []
    try { return JSON.parse(value) as string[] } catch { return [] }
  }

  async getRoles(): Promise<RoleDefinition[]> {
    const names = await this.client.smembers(this.rolesSetKey())
    const roles: RoleDefinition[] = []
    for (const name of names) {
      const hash = await this.client.hgetall(this.roleKey(name))
      if (hash) {
        roles.push({
          name: hash.name ?? name,
          level: Number(hash.level ?? 1),
          permissions: this.parseJsonField(hash.permissions),
        })
      }
    }
    return roles
  }

  async getPermissions(role: string): Promise<string[]> {
    const hash = await this.client.hgetall(this.roleKey(role))
    return this.parseJsonField(hash?.permissions)
  }

  async saveRole(role: RoleDefinition): Promise<void> {
    await this.client.hset(
      this.roleKey(role.name),
      'name', role.name,
      'level', role.level,
      'permissions', JSON.stringify(role.permissions),
    )
    await this.client.sadd(this.rolesSetKey(), role.name)
  }

  async deleteRole(role: string): Promise<void> {
    await this.client.del(this.roleKey(role))
    await this.client.srem(this.rolesSetKey(), role)
  }

  async grantPermission(role: string, permission: string): Promise<void> {
    const current = await this.getPermissions(role)
    if (current.includes(permission)) return
    await this.client.hset(this.roleKey(role), 'permissions', JSON.stringify([...current, permission]))
  }

  async revokePermission(role: string, permission: string): Promise<void> {
    const current = await this.getPermissions(role)
    await this.client.hset(this.roleKey(role), 'permissions', JSON.stringify(current.filter((p) => p !== permission)))
  }

  async getDeniedPermissions(role: string): Promise<string[]> {
    const hash = await this.client.hgetall(this.roleKey(role))
    return this.parseJsonField(hash?.denied_permissions)
  }

  async saveDeny(role: string, permission: string): Promise<void> {
    const current = await this.getDeniedPermissions(role)
    if (current.includes(permission)) return
    await this.client.hset(this.roleKey(role), 'denied_permissions', JSON.stringify([...current, permission]))
  }

  async removeDeny(role: string, permission: string): Promise<void> {
    const current = await this.getDeniedPermissions(role)
    await this.client.hset(this.roleKey(role), 'denied_permissions', JSON.stringify(current.filter((p) => p !== permission)))
  }

  async assignRole(userId: string, roleName: string, tenantId?: string): Promise<void> {
    await this.client.sadd(this.userRolesKey(userId, tenantId), roleName)
  }

  async revokeRole(userId: string, roleName: string, tenantId?: string): Promise<void> {
    await this.client.srem(this.userRolesKey(userId, tenantId), roleName)
  }

  async getUserRoles(userId: string, tenantId?: string): Promise<string[]> {
    return this.client.smembers(this.userRolesKey(userId, tenantId))
  }
}
