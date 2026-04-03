import { describe, it, expect, beforeEach } from 'vitest'
import { PolicyEngine } from '../src/policy'
import { UnknownRoleError } from '../src/errors'

describe('delegate()', () => {
  let policy: PolicyEngine

  beforeEach(() => {
    policy = new PolicyEngine({
      roles: [
        { name: 'USER', level: 0, permissions: ['posts:read'] },
        { name: 'ADMIN', level: 80, permissions: ['posts:read', 'users:delete'] },
      ],
    })
  })

  it('returns a context that passes ADMIN permission checks', () => {
    const ctx = policy.delegate('ADMIN')
    expect(ctx.can('users:delete')).toBe(true)
    expect(ctx.can('posts:read')).toBe(true)
  })

  it('scoped delegation: only posts:read passes, not users:delete', () => {
    const ctx = policy.delegate('ADMIN', { scope: ['posts:read'] })
    expect(ctx.can('posts:read')).toBe(true)
    expect(ctx.can('users:delete')).toBe(false)
  })

  it('multi-role delegation gets union of permissions', () => {
    policy.addRole({ name: 'MODERATOR', level: 40, permissions: ['posts:delete'] })
    const ctx = policy.delegate(['USER', 'MODERATOR'])
    expect(ctx.can('posts:read')).toBe(true)
    expect(ctx.can('posts:delete')).toBe(true)
    expect(ctx.can('users:delete')).toBe(false)
  })

  it('throws UnknownRoleError for an unknown role', () => {
    expect(() => policy.delegate('GHOST')).toThrow(UnknownRoleError)
  })

  it('empty scope blocks all permissions', () => {
    const ctx = policy.delegate('ADMIN', { scope: [] })
    expect(ctx.can('posts:read')).toBe(false)
    expect(ctx.can('users:delete')).toBe(false)
  })

  it('stores delegatedBy metadata on opts without affecting permission checks', () => {
    const ctx = policy.delegate('ADMIN', { delegatedBy: 'superuser', scope: ['posts:read'] })
    expect(ctx.can('posts:read')).toBe(true)
    expect(ctx.can('users:delete')).toBe(false)
  })
})

describe('delegateUser()', () => {
  it('fetches roles from adapter and returns a delegated context', async () => {
    const policy = new PolicyEngine({
      roles: [
        { name: 'ADMIN', level: 80, permissions: ['users:delete', 'posts:read'] },
      ],
    })

    const adapter = {
      getRoles: async () => [],
      getPermissions: async () => [],
      saveRole: async () => {},
      deleteRole: async () => {},
      grantPermission: async () => {},
      revokePermission: async () => {},
      getDeniedPermissions: async () => [],
      saveDeny: async () => {},
      removeDeny: async () => {},
      assignRole: async () => {},
      revokeRole: async () => {},
      getUserRoles: async (userId: string) => (userId === 'alice' ? ['ADMIN'] : []),
    }

    // Attach adapter via fromAdapter workaround — use internal method directly
    // by constructing an engine that already has the adapter
    const engine = await PolicyEngine.fromAdapter({
      ...adapter,
      getRoles: async () => [{ name: 'ADMIN', level: 80, permissions: ['users:delete', 'posts:read'] }],
      getPermissions: async () => [],
      getDeniedPermissions: async () => [],
    })

    const ctx = await engine.delegateUser('alice')
    expect(ctx.can('users:delete')).toBe(true)
  })

  it('scoped delegateUser: limits permissions to scope', async () => {
    const engine = await PolicyEngine.fromAdapter({
      getRoles: async () => [{ name: 'ADMIN', level: 80, permissions: ['users:delete', 'posts:read'] }],
      getPermissions: async () => [],
      getDeniedPermissions: async () => [],
      saveRole: async () => {},
      deleteRole: async () => {},
      grantPermission: async () => {},
      revokePermission: async () => {},
      saveDeny: async () => {},
      removeDeny: async () => {},
      assignRole: async () => {},
      revokeRole: async () => {},
      getUserRoles: async () => ['ADMIN'],
    })

    const ctx = await engine.delegateUser('alice', undefined, { scope: ['posts:read'] })
    expect(ctx.can('posts:read')).toBe(true)
    expect(ctx.can('users:delete')).toBe(false)
  })
})
