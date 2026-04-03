import { describe, it, expect } from 'vitest'
import { PolicyEngine } from '../src/policy'
import type { PolicySnapshot, RoleDefinition } from '../src/types'

const CSV_WITH_HEADER = `role,level,permissions,groups
GUEST,0,"posts:read,comments:read",
USER,20,"posts:write","read-group"
ADMIN,80,"*",`

const CSV_WITHOUT_HEADER = `GUEST,0,"posts:read,comments:read",
USER,20,"posts:write","read-group"
ADMIN,80,"*",`

describe('PolicyEngine.fromCSV', () => {
  it('parses CSV with a header row', () => {
    const engine = PolicyEngine.fromCSV(CSV_WITH_HEADER)
    const roles = engine.listRoles()
    expect(roles).toHaveLength(3)

    const guest = roles.find(r => r.name === 'GUEST')!
    expect(guest.level).toBe(0)
    expect(guest.permissions).toEqual(['posts:read', 'comments:read'])
    expect(guest.groups).toBeUndefined()

    const user = roles.find(r => r.name === 'USER')!
    expect(user.level).toBe(20)
    expect(user.permissions).toEqual(['posts:write'])
    expect(user.groups).toEqual(['read-group'])

    const admin = roles.find(r => r.name === 'ADMIN')!
    expect(admin.level).toBe(80)
    expect(admin.permissions).toEqual(['*'])
  })

  it('parses CSV without a header row', () => {
    const engine = PolicyEngine.fromCSV(CSV_WITHOUT_HEADER)
    const roles = engine.listRoles()
    expect(roles).toHaveLength(3)

    const guest = roles.find(r => r.name === 'GUEST')!
    expect(guest.level).toBe(0)
    expect(guest.permissions).toEqual(['posts:read', 'comments:read'])
  })

  it('returns an empty engine for an empty CSV string', () => {
    const engine = PolicyEngine.fromCSV('   ')
    expect(engine.listRoles()).toHaveLength(0)
  })

  it('parses groups column correctly', () => {
    const csv = `role,level,permissions,groups
MOD,50,"posts:delete","mod-group,admin-group"`
    const engine = PolicyEngine.fromCSV(csv)
    const mod = engine.listRoles()[0]
    expect(mod.groups).toEqual(['mod-group', 'admin-group'])
  })
})

describe('PolicyEngine toCSV / fromCSV round-trip', () => {
  it('round-trips through toCSV and fromCSV producing identical roles', () => {
    const original = PolicyEngine.fromCSV(CSV_WITH_HEADER)
    const csv = original.toCSV()
    const restored = PolicyEngine.fromCSV(csv)

    const originalRoles = original.listRoles()
    const restoredRoles = restored.listRoles()

    expect(restoredRoles).toHaveLength(originalRoles.length)
    for (const orig of originalRoles) {
      const rest = restoredRoles.find(r => r.name === orig.name)!
      expect(rest).toBeDefined()
      expect(rest.level).toBe(orig.level)
      expect(rest.permissions).toEqual(orig.permissions)
      expect(rest.groups ?? []).toEqual(orig.groups ?? [])
    }
  })

  it('toCSV produces a header row as the first line', () => {
    const engine = PolicyEngine.fromCSV(CSV_WITH_HEADER)
    const csv = engine.toCSV()
    expect(csv.split('\n')[0]).toBe('role,level,permissions,groups')
  })
})

describe('PolicyEngine.fromBulkJSON', () => {
  const rolesArray: RoleDefinition[] = [
    { name: 'GUEST', level: 0, permissions: ['posts:read'] },
    { name: 'ADMIN', level: 80, permissions: ['*'] },
  ]

  const snapshot: PolicySnapshot = {
    roles: rolesArray,
    denies: { GUEST: ['posts:delete'] },
    groups: { 'read-group': ['posts:read', 'comments:read'] },
  }

  it('creates an engine from a RoleDefinition array (object)', () => {
    const engine = PolicyEngine.fromBulkJSON(rolesArray)
    const roles = engine.listRoles()
    expect(roles).toHaveLength(2)
    expect(roles.find(r => r.name === 'GUEST')?.level).toBe(0)
    expect(roles.find(r => r.name === 'ADMIN')?.level).toBe(80)
  })

  it('creates an engine from a RoleDefinition array (JSON string)', () => {
    const engine = PolicyEngine.fromBulkJSON(JSON.stringify(rolesArray))
    expect(engine.listRoles()).toHaveLength(2)
  })

  it('creates an engine from a PolicySnapshot object', () => {
    const engine = PolicyEngine.fromBulkJSON(snapshot)
    const roles = engine.listRoles()
    expect(roles).toHaveLength(2)
    // Denies from the snapshot should be respected
    expect(engine.cannot('GUEST', 'posts:delete')).toBe(true)
  })

  it('creates an engine from a PolicySnapshot JSON string', () => {
    const engine = PolicyEngine.fromBulkJSON(JSON.stringify(snapshot))
    expect(engine.listRoles()).toHaveLength(2)
    expect(engine.cannot('GUEST', 'posts:delete')).toBe(true)
  })

  it('accepts an already-parsed object (no double-parse)', () => {
    const engine = PolicyEngine.fromBulkJSON(rolesArray)
    expect(engine.listRoles().map(r => r.name)).toEqual(['GUEST', 'ADMIN'])
  })
})
