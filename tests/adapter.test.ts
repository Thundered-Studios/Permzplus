import { describe, it, expect, beforeEach } from 'vitest'
import { InMemoryAdapter } from '../src/adapter'
import { PolicyEngine } from '../src/policy'

describe('InMemoryAdapter', () => {
  let adapter: InMemoryAdapter

  beforeEach(() => {
    adapter = new InMemoryAdapter()
  })

  it('getRoles() returns empty array initially', async () => {
    const roles = await adapter.getRoles()
    expect(roles).toEqual([])
  })

  it('saveRole then getRoles includes the new role', async () => {
    await adapter.saveRole({ name: 'TEST', level: 10, permissions: [] })
    const roles = await adapter.getRoles()
    expect(roles.some((r) => r.name === 'TEST')).toBe(true)
  })

  it('grantPermission then getPermissions includes the permission', async () => {
    await adapter.saveRole({ name: 'TEST', level: 10, permissions: [] })
    await adapter.grantPermission('TEST', 'x:y')
    const perms = await adapter.getPermissions('TEST')
    expect(perms).toContain('x:y')
  })

  it('revokePermission removes the permission', async () => {
    await adapter.saveRole({ name: 'TEST', level: 10, permissions: [] })
    await adapter.grantPermission('TEST', 'x:y')
    await adapter.revokePermission('TEST', 'x:y')
    const perms = await adapter.getPermissions('TEST')
    expect(perms).not.toContain('x:y')
  })

  it('deleteRole removes the role', async () => {
    await adapter.saveRole({ name: 'TEST', level: 10, permissions: [] })
    await adapter.deleteRole('TEST')
    const roles = await adapter.getRoles()
    expect(roles.some((r) => r.name === 'TEST')).toBe(false)
  })
})

describe('PolicyEngine.fromAdapter', () => {
  it('seeds built-in roles — adapter includes GUEST after fromAdapter', async () => {
    const adapter = new InMemoryAdapter()
    await PolicyEngine.fromAdapter(adapter)
    const roles = await adapter.getRoles()
    expect(roles.some((r) => r.name === 'GUEST')).toBe(true)
  })

  it('SUPER_ADMIN can anything:ever after fromAdapter', async () => {
    const adapter = new InMemoryAdapter()
    const policy = await PolicyEngine.fromAdapter(adapter)
    expect(policy.can('SUPER_ADMIN', 'anything:ever')).toBe(true)
  })

  it('custom role saved to adapter before fromAdapter is loaded into the engine', async () => {
    const adapter = new InMemoryAdapter()
    await adapter.saveRole({ name: 'CUSTOM', level: 5, permissions: ['custom:action'] })
    await adapter.grantPermission('CUSTOM', 'custom:action')
    const policy = await PolicyEngine.fromAdapter(adapter)
    expect(policy.can('CUSTOM', 'custom:action')).toBe(true)
  })
})
