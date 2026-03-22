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
  it('engine starts empty when adapter has no roles', async () => {
    const adapter = new InMemoryAdapter()
    const policy = await PolicyEngine.fromAdapter(adapter)
    const roles = await adapter.getRoles()
    expect(roles).toHaveLength(0)
    expect(() => policy.can('GUEST', 'posts:read')).toThrow()
  })

  it('role saved to adapter before fromAdapter is loaded into the engine', async () => {
    const adapter = new InMemoryAdapter()
    await adapter.saveRole({ name: 'CUSTOM', level: 5, permissions: ['custom:action'] })
    const policy = await PolicyEngine.fromAdapter(adapter)
    expect(policy.can('CUSTOM', 'custom:action')).toBe(true)
  })

  it('permissions granted to adapter before fromAdapter are loaded into the engine', async () => {
    const adapter = new InMemoryAdapter()
    await adapter.saveRole({ name: 'EDITOR', level: 10, permissions: [] })
    await adapter.grantPermission('EDITOR', 'posts:write')
    const policy = await PolicyEngine.fromAdapter(adapter)
    expect(policy.can('EDITOR', 'posts:write')).toBe(true)
  })
})
