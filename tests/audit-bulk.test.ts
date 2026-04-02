import { describe, it, expect, beforeEach } from 'vitest'
import { PolicyEngine } from '../src/policy'
import { InMemoryAdapter } from '../src/adapter'
import { InMemoryAuditLogger } from '../src/audit'
import { createTestPolicy, expectCan, expectCannot, diffPolicies } from '../src/testing'
import type { RoleDefinition } from '../src/types'

const ROLES: RoleDefinition[] = [
  { name: 'VIEWER', level: 1, permissions: ['posts:read'] },
  { name: 'EDITOR', level: 5, permissions: ['posts:write', 'posts:edit'] },
  { name: 'ADMIN', level: 10, permissions: ['users:manage'] },
]

// ---------------------------------------------------------------------------
// Audit logging
// ---------------------------------------------------------------------------

describe('InMemoryAuditLogger', () => {
  it('records role.add events', () => {
    const audit = new InMemoryAuditLogger()
    const policy = new PolicyEngine({ audit })
    policy.addRole({ name: 'MOD', level: 3, permissions: ['posts:delete'] })

    const events = audit.getEventsFor('role.add')
    expect(events).toHaveLength(1)
    expect(events[0].role).toBe('MOD')
    expect(events[0].timestamp).toBeInstanceOf(Date)
  })

  it('records role.remove events', () => {
    const audit = new InMemoryAuditLogger()
    const policy = new PolicyEngine({ roles: ROLES, audit })
    policy.removeRole('VIEWER')

    const events = audit.getEventsFor('role.remove')
    expect(events).toHaveLength(1)
    expect(events[0].role).toBe('VIEWER')
  })

  it('records permission.grant events', () => {
    const audit = new InMemoryAuditLogger()
    const policy = new PolicyEngine({ roles: ROLES, audit })
    policy.grantTo('EDITOR', 'comments:write')

    const events = audit.getEventsFor('permission.grant')
    expect(events).toHaveLength(1)
    expect(events[0]).toMatchObject({ role: 'EDITOR', permission: 'comments:write' })
  })

  it('records permission.revoke events', () => {
    const audit = new InMemoryAuditLogger()
    const policy = new PolicyEngine({ roles: ROLES, audit })
    policy.revokeFrom('EDITOR', 'posts:write')

    const events = audit.getEventsFor('permission.revoke')
    expect(events).toHaveLength(1)
    expect(events[0]).toMatchObject({ role: 'EDITOR', permission: 'posts:write' })
  })

  it('records permission.deny and permission.removeDeny events', () => {
    const audit = new InMemoryAuditLogger()
    const policy = new PolicyEngine({ roles: ROLES, audit })
    policy.denyFrom('EDITOR', 'posts:read')
    policy.removeDeny('EDITOR', 'posts:read')

    expect(audit.getEventsFor('permission.deny')).toHaveLength(1)
    expect(audit.getEventsFor('permission.removeDeny')).toHaveLength(1)
  })

  it('records user.assignRole and user.revokeRole events', async () => {
    const audit = new InMemoryAuditLogger()
    const adapter = new InMemoryAdapter()
    const policy = await PolicyEngine.fromAdapter(adapter)
    ;(policy as any).auditLogger = audit // inject after fromAdapter
    // Re-add roles so the engine knows them
    const p = new PolicyEngine({ roles: ROLES, audit })
    const a = new InMemoryAdapter()
    await a.saveRole(ROLES[0])
    const p2 = await PolicyEngine.fromAdapter(a)
    ;(p2 as any).auditLogger = audit

    const p3 = new PolicyEngine({ roles: ROLES, audit })
    const a3 = new InMemoryAdapter()
    const p4 = new PolicyEngine({ roles: ROLES, audit })
    const a4 = new InMemoryAdapter()

    // Use a fresh policy with adapter directly
    const engine = new PolicyEngine({ roles: ROLES, audit })
    ;(engine as any).adapter = new InMemoryAdapter()
    ;(engine as any).adapter.assignRole = async (u: string, r: string) => {}
    ;(engine as any).adapter.revokeRole = async (u: string, r: string) => {}
    ;(engine as any).adapter.getUserRoles = async () => []
    await engine.assignRole('user-1', 'VIEWER')
    await engine.revokeRole('user-1', 'VIEWER')

    expect(audit.getEventsFor('user.assignRole')).toHaveLength(1)
    expect(audit.getEventsFor('user.revokeRole')).toHaveLength(1)
    expect(audit.getEventsFor('user.assignRole')[0]).toMatchObject({
      role: 'VIEWER',
      userId: 'user-1',
    })
  })

  it('getEvents returns all events in order', () => {
    const audit = new InMemoryAuditLogger()
    const policy = new PolicyEngine({ roles: ROLES, audit })
    policy.grantTo('EDITOR', 'comments:write')
    policy.revokeFrom('EDITOR', 'comments:write')

    const events = audit.getEvents()
    expect(events[0].action).toBe('permission.grant')
    expect(events[1].action).toBe('permission.revoke')
  })

  it('clear() empties the log', () => {
    const audit = new InMemoryAuditLogger()
    const policy = new PolicyEngine({ roles: ROLES, audit })
    policy.grantTo('EDITOR', 'comments:write')
    expect(audit.getEvents()).toHaveLength(1)
    audit.clear()
    expect(audit.getEvents()).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// Bulk operations
// ---------------------------------------------------------------------------

describe('PolicyEngine — bulk operations', () => {
  let policy: PolicyEngine

  beforeEach(() => {
    policy = new PolicyEngine({ roles: ROLES })
  })

  it('addRoles() registers all roles', () => {
    const fresh = new PolicyEngine()
    fresh.addRoles(ROLES)
    expect(fresh.listRoles().map((r) => r.name)).toEqual(
      expect.arrayContaining(['VIEWER', 'EDITOR', 'ADMIN']),
    )
  })

  it('grantBulk() grants multiple permissions at once', () => {
    policy.grantBulk('EDITOR', ['comments:read', 'comments:write'])
    expect(policy.can('EDITOR', 'comments:read')).toBe(true)
    expect(policy.can('EDITOR', 'comments:write')).toBe(true)
  })

  it('grantBulk() does not duplicate permissions', () => {
    policy.grantBulk('EDITOR', ['posts:write', 'posts:write'])
    const perms = policy.getPermissions('EDITOR').filter((p) => p === 'posts:write')
    expect(perms).toHaveLength(1)
  })

  it('grantBulk() fires audit events for each permission', () => {
    const audit = new InMemoryAuditLogger()
    const p = new PolicyEngine({ roles: ROLES, audit })
    p.grantBulk('EDITOR', ['comments:read', 'comments:write'])
    expect(audit.getEventsFor('permission.grant')).toHaveLength(2)
  })

  it('revokeBulk() removes multiple permissions at once', () => {
    policy.revokeBulk('EDITOR', ['posts:write', 'posts:edit'])
    expect(policy.cannot('EDITOR', 'posts:write')).toBe(true)
    expect(policy.cannot('EDITOR', 'posts:edit')).toBe(true)
  })

  it('revokeBulk() fires audit events for each permission', () => {
    const audit = new InMemoryAuditLogger()
    const p = new PolicyEngine({ roles: ROLES, audit })
    p.revokeBulk('EDITOR', ['posts:write', 'posts:edit'])
    expect(audit.getEventsFor('permission.revoke')).toHaveLength(2)
  })

  it('denyBulk() denies multiple permissions at once', () => {
    policy.denyBulk('EDITOR', ['posts:read', 'posts:write'])
    expect(policy.cannot('EDITOR', 'posts:read')).toBe(true)
    expect(policy.cannot('EDITOR', 'posts:write')).toBe(true)
  })

  it('denyBulk() fires audit events for each permission', () => {
    const audit = new InMemoryAuditLogger()
    const p = new PolicyEngine({ roles: ROLES, audit })
    p.denyBulk('EDITOR', ['posts:read', 'posts:write'])
    expect(audit.getEventsFor('permission.deny')).toHaveLength(2)
  })

  it('assignRoles() assigns multiple roles in one call', async () => {
    const adapter = new InMemoryAdapter()
    for (const r of ROLES) await adapter.saveRole(r)
    const engine = await PolicyEngine.fromAdapter(adapter)
    await engine.assignRoles('user-1', ['VIEWER', 'EDITOR'])
    const assigned = await engine.getUserRoles('user-1')
    expect(assigned).toContain('VIEWER')
    expect(assigned).toContain('EDITOR')
  })

  it('revokeRoles() revokes multiple roles in one call', async () => {
    const adapter = new InMemoryAdapter()
    for (const r of ROLES) await adapter.saveRole(r)
    const engine = await PolicyEngine.fromAdapter(adapter)
    await engine.assignRoles('user-1', ['VIEWER', 'EDITOR'])
    await engine.revokeRoles('user-1', ['VIEWER', 'EDITOR'])
    const assigned = await engine.getUserRoles('user-1')
    expect(assigned).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// Testing utilities
// ---------------------------------------------------------------------------

describe('Testing utilities', () => {
  it('createTestPolicy builds a policy from role definitions', () => {
    const policy = createTestPolicy(ROLES)
    expect(policy.can('VIEWER', 'posts:read')).toBe(true)
  })

  it('expectCan passes when permission is held', () => {
    const policy = createTestPolicy(ROLES)
    const ctx = policy.createContext('ADMIN')
    expect(() => expectCan(ctx, 'users:manage')).not.toThrow()
  })

  it('expectCan throws when permission is missing', () => {
    const policy = createTestPolicy(ROLES)
    const ctx = policy.createContext('VIEWER')
    expect(() => expectCan(ctx, 'users:manage')).toThrow(/expectCan failed/)
  })

  it('expectCan includes reason in error message', () => {
    const policy = createTestPolicy(ROLES)
    const ctx = policy.createContext('VIEWER')
    expect(() => expectCan(ctx, 'users:manage')).toThrow(/Reason:/)
  })

  it('expectCannot passes when permission is absent', () => {
    const policy = createTestPolicy(ROLES)
    const ctx = policy.createContext('VIEWER')
    expect(() => expectCannot(ctx, 'users:manage')).not.toThrow()
  })

  it('expectCannot throws when permission is unexpectedly present', () => {
    const policy = createTestPolicy(ROLES)
    const ctx = policy.createContext('ADMIN')
    expect(() => expectCannot(ctx, 'users:manage')).toThrow(/expectCannot failed/)
  })

  it('diffPolicies reports added roles', () => {
    const before = createTestPolicy(ROLES)
    const after = createTestPolicy([
      ...ROLES,
      { name: 'SUPERADMIN', level: 100, permissions: ['*'] },
    ])
    const diff = diffPolicies(before, after)
    expect(diff.rolesAdded).toContain('SUPERADMIN')
    expect(diff.rolesRemoved).toHaveLength(0)
  })

  it('diffPolicies reports removed roles', () => {
    const before = createTestPolicy(ROLES)
    const after = createTestPolicy(ROLES.slice(1))
    const diff = diffPolicies(before, after)
    expect(diff.rolesRemoved).toContain('VIEWER')
  })

  it('diffPolicies reports granted permissions', () => {
    const before = createTestPolicy(ROLES)
    const after = createTestPolicy([
      ...ROLES.slice(0, 2),
      { name: 'ADMIN', level: 10, permissions: ['users:manage', 'settings:edit'] },
    ])
    const diff = diffPolicies(before, after)
    expect(diff.permissionsGranted['ADMIN']).toContain('settings:edit')
  })

  it('diffPolicies reports revoked permissions', () => {
    const before = createTestPolicy(ROLES)
    const after = createTestPolicy([
      ROLES[0],
      { name: 'EDITOR', level: 5, permissions: ['posts:write'] },
      ROLES[2],
    ])
    const diff = diffPolicies(before, after)
    expect(diff.permissionsRevoked['EDITOR']).toContain('posts:edit')
  })
})
