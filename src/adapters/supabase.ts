/**
 * Supabase adapter for PermzPlus.
 *
 * Uses two tables in your Supabase project:
 *   - `permzplus_roles`      — role definitions
 *   - `permzplus_user_roles` — user-role assignments
 *
 * Run the following SQL in your Supabase SQL editor to create the schema:
 *
 * ```sql
 * create table if not exists permzplus_roles (
 *   name                text primary key,
 *   level               integer not null default 1,
 *   permissions         text[]  not null default '{}',
 *   denied_permissions  text[]  not null default '{}'
 * );
 *
 * create table if not exists permzplus_user_roles (
 *   user_id   text    not null,
 *   role_name text    not null references permzplus_roles(name) on delete cascade,
 *   tenant_id text,
 *   primary key (user_id, role_name, coalesce(tenant_id, ''))
 * );
 * create index if not exists permzplus_user_roles_user_id on permzplus_user_roles(user_id);
 * ```
 *
 * @example
 * ```ts
 * import { createClient } from '@supabase/supabase-js'
 * import { PolicyEngine } from 'permzplus'
 * import { SupabaseAdapter } from 'permzplus/adapters/supabase'
 *
 * const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
 * const adapter = new SupabaseAdapter(supabase)
 * const policy = await PolicyEngine.fromAdapter(adapter)
 * ```
 */

import type { PermzAdapter, RoleDefinition } from '../types'

// ---------------------------------------------------------------------------
// Minimal Supabase type shim
// ---------------------------------------------------------------------------

interface SupabaseResponse<T> {
  data: T | null
  error: { message: string } | null
}

interface SupabaseQueryBuilder<T> {
  select(columns?: string): SupabaseQueryBuilder<T>
  insert(values: Record<string, unknown> | Record<string, unknown>[]): SupabaseQueryBuilder<T>
  update(values: Record<string, unknown>): SupabaseQueryBuilder<T>
  upsert(values: Record<string, unknown> | Record<string, unknown>[], opts?: { onConflict?: string }): SupabaseQueryBuilder<T>
  delete(): SupabaseQueryBuilder<T>
  eq(column: string, value: unknown): SupabaseQueryBuilder<T>
  is(column: string, value: null): SupabaseQueryBuilder<T>
  single(): Promise<SupabaseResponse<T>>
  maybeSingle(): Promise<SupabaseResponse<T | null>>
  then: Promise<SupabaseResponse<T[]>>['then']
}

interface SupabaseClient {
  from(table: string): SupabaseQueryBuilder<Record<string, unknown>>
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface SupabaseAdapterOptions {
  /** Table that stores role definitions. @default "permzplus_roles" */
  rolesTable?: string
  /** Table that stores user-role assignments. @default "permzplus_user_roles" */
  userRolesTable?: string
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

export class SupabaseAdapter implements PermzAdapter {
  private client: SupabaseClient
  private rolesTable: string
  private userRolesTable: string

  constructor(client: SupabaseClient, options?: SupabaseAdapterOptions) {
    this.client = client
    this.rolesTable = options?.rolesTable ?? 'permzplus_roles'
    this.userRolesTable = options?.userRolesTable ?? 'permzplus_user_roles'
  }

  private throwOnError(res: SupabaseResponse<unknown>, context: string): void {
    if (res.error) throw new Error(`[SupabaseAdapter] ${context}: ${res.error.message}`)
  }

  async getRoles(): Promise<RoleDefinition[]> {
    const res = await (this.client.from(this.rolesTable).select('name,level,permissions') as unknown as Promise<SupabaseResponse<Record<string, unknown>[]>>)
    this.throwOnError(res, 'getRoles')
    return (res.data ?? []).map((row) => ({
      name: String(row.name),
      level: Number(row.level ?? 1),
      permissions: Array.isArray(row.permissions) ? (row.permissions as string[]) : [],
    }))
  }

  async getPermissions(role: string): Promise<string[]> {
    const res = await this.client.from(this.rolesTable).select('permissions').eq('name', role).single()
    if (!res.data) return []
    return Array.isArray((res.data as Record<string, unknown>).permissions)
      ? ((res.data as Record<string, unknown>).permissions as string[])
      : []
  }

  async saveRole(role: RoleDefinition): Promise<void> {
    const res = await this.client.from(this.rolesTable).upsert(
      { name: role.name, level: role.level, permissions: role.permissions },
      { onConflict: 'name' },
    ).single()
    this.throwOnError(res, 'saveRole')
  }

  async deleteRole(role: string): Promise<void> {
    const res = await this.client.from(this.rolesTable).delete().eq('name', role).single()
    this.throwOnError(res, 'deleteRole')
  }

  async grantPermission(role: string, permission: string): Promise<void> {
    const current = await this.getPermissions(role)
    if (current.includes(permission)) return
    const res = await this.client.from(this.rolesTable)
      .update({ permissions: [...current, permission] })
      .eq('name', role)
      .single()
    this.throwOnError(res, 'grantPermission')
  }

  async revokePermission(role: string, permission: string): Promise<void> {
    const current = await this.getPermissions(role)
    const res = await this.client.from(this.rolesTable)
      .update({ permissions: current.filter((p) => p !== permission) })
      .eq('name', role)
      .single()
    this.throwOnError(res, 'revokePermission')
  }

  async getDeniedPermissions(role: string): Promise<string[]> {
    const res = await this.client.from(this.rolesTable).select('denied_permissions').eq('name', role).single()
    if (!res.data) return []
    return Array.isArray((res.data as Record<string, unknown>).denied_permissions)
      ? ((res.data as Record<string, unknown>).denied_permissions as string[])
      : []
  }

  async saveDeny(role: string, permission: string): Promise<void> {
    const current = await this.getDeniedPermissions(role)
    if (current.includes(permission)) return
    const res = await this.client.from(this.rolesTable)
      .update({ denied_permissions: [...current, permission] })
      .eq('name', role)
      .single()
    this.throwOnError(res, 'saveDeny')
  }

  async removeDeny(role: string, permission: string): Promise<void> {
    const current = await this.getDeniedPermissions(role)
    const res = await this.client.from(this.rolesTable)
      .update({ denied_permissions: current.filter((p) => p !== permission) })
      .eq('name', role)
      .single()
    this.throwOnError(res, 'removeDeny')
  }

  async assignRole(userId: string, roleName: string, tenantId?: string): Promise<void> {
    const res = await this.client.from(this.userRolesTable).upsert(
      { user_id: userId, role_name: roleName, tenant_id: tenantId ?? null },
      { onConflict: 'user_id,role_name,tenant_id' },
    ).single()
    this.throwOnError(res, 'assignRole')
  }

  async revokeRole(userId: string, roleName: string, tenantId?: string): Promise<void> {
    let q = this.client.from(this.userRolesTable).delete().eq('user_id', userId).eq('role_name', roleName)
    q = tenantId ? q.eq('tenant_id', tenantId) : q.is('tenant_id', null)
    const res = await q.single()
    this.throwOnError(res, 'revokeRole')
  }

  async getUserRoles(userId: string, tenantId?: string): Promise<string[]> {
    let q = this.client.from(this.userRolesTable).select('role_name').eq('user_id', userId)
    q = tenantId ? q.eq('tenant_id', tenantId) : q.is('tenant_id', null)
    const res = await (q as unknown as Promise<SupabaseResponse<Record<string, unknown>[]>>)
    return (res.data ?? []).map((row) => String(row.role_name))
  }
}
