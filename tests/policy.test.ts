import { describe, it, expect, beforeEach } from 'vitest'
import { PolicyEngine } from '../src/policy'
import { PermissionDeniedError, UnknownRoleError, InvalidPermissionError } from '../src/errors'
import type { RoleDefinition } from '../src/types'

const TEST_ROLES: RoleDefinition[] = [
  { name: 'GUEST', level: 0, permissions: ['posts:read'] },
  { name: 'USER', level: 20, permissions: ['posts:write', 'comments:read', 'comments:write'] },
  { name: 'MODERATOR', level: 40, permissions: ['posts:delete', 'comments:delete', 'users:warn'] },
  { name: 'DEVELOPER', level: 60, permissions: ['admin:debug', 'admin:logs'] },
  { name: 'ADMIN', level: 80, permissions: ['users:ban', 'users:delete', 'admin:panel'] },
  { name: 'SUPER_ADMIN', level: 100, permissions: ['*'] },
]

describe('PolicyEngine — roles loaded via options.roles', () => {
  let policy: PolicyEngine

  beforeEach(() => {
    policy = new PolicyEngine({ roles: TEST_ROLES })
  })

  it('GUEST can posts:read', () => {
    expect(policy.can('GUEST', 'posts:read')).toBe(true)
  })

  it('USER can posts:read (inherited from GUEST)', () => {
    expect(policy.can('USER', 'posts:read')).toBe(true)
  })

  it('SUPER_ADMIN can anything:ever (wildcard)', () => {
    expect(policy.can('SUPER_ADMIN', 'anything:ever')).toBe(true)
  })

  it('MODERATOR can posts:write (inherited from USER)', () => {
    expect(policy.can('MODERATOR', 'posts:write')).toBe(true)
  })
})

describe('PolicyEngine — custom roles via options.roles', () => {
  let policy: PolicyEngine

  beforeEach(() => {
    policy = new PolicyEngine({
      roles: [
        { name: 'BASE', level: 0, permissions: ['posts:read'] },
        { name: 'WRITER', level: 20, permissions: ['posts:write'] },
        { name: 'TESTER', level: 15, permissions: ['tests:run'] },
      ],
    })
  })

  it('TESTER can posts:read (inherited from BASE at level 0)', () => {
    expect(policy.can('TESTER', 'posts:read')).toBe(true)
  })

  it('TESTER can tests:run (own permission)', () => {
    expect(policy.can('TESTER', 'tests:run')).toBe(true)
  })

  it('TESTER cannot posts:write (WRITER is level 20, TESTER is 15)', () => {
    expect(policy.can('TESTER', 'posts:write')).toBe(false)
  })
})

describe('PolicyEngine — extra permissions via options.permissions', () => {
  it('GUEST can extra:action when added via options.permissions', () => {
    const policy = new PolicyEngine({
      roles: [{ name: 'GUEST', level: 0, permissions: ['posts:read'] }],
      permissions: { GUEST: ['extra:action'] },
    })
    expect(policy.can('GUEST', 'extra:action')).toBe(true)
  })
})

describe('PolicyEngine — cannot', () => {
  let policy: PolicyEngine

  beforeEach(() => {
    policy = new PolicyEngine({ roles: TEST_ROLES })
  })

  it('USER cannot users:ban', () => {
    expect(policy.cannot('USER', 'users:ban')).toBe(true)
  })

  it('ADMIN can users:ban (cannot returns false)', () => {
    expect(policy.cannot('ADMIN', 'users:ban')).toBe(false)
  })
})

describe('PolicyEngine — assert', () => {
  let policy: PolicyEngine

  beforeEach(() => {
    policy = new PolicyEngine({ roles: TEST_ROLES })
  })

  it('does not throw when ADMIN asserts users:ban', () => {
    expect(() => policy.assert('ADMIN', 'users:ban')).not.toThrow()
  })

  it('throws PermissionDeniedError when USER asserts users:ban', () => {
    expect(() => policy.assert('USER', 'users:ban')).toThrow(PermissionDeniedError)
  })
})

describe('PolicyEngine — getRoleLevel', () => {
  let policy: PolicyEngine

  beforeEach(() => {
    policy = new PolicyEngine({ roles: TEST_ROLES })
  })

  it('returns 0 for GUEST', () => {
    expect(policy.getRoleLevel('GUEST')).toBe(0)
  })

  it('returns 100 for SUPER_ADMIN', () => {
    expect(policy.getRoleLevel('SUPER_ADMIN')).toBe(100)
  })

  it('throws UnknownRoleError for unregistered role', () => {
    expect(() => policy.getRoleLevel('PHANTOM')).toThrow(UnknownRoleError)
  })
})

describe('PolicyEngine — isAtLeast', () => {
  let policy: PolicyEngine

  beforeEach(() => {
    policy = new PolicyEngine({ roles: TEST_ROLES })
  })

  it('ADMIN isAtLeast MODERATOR is true', () => {
    expect(policy.isAtLeast('ADMIN', 'MODERATOR')).toBe(true)
  })

  it('USER isAtLeast ADMIN is false', () => {
    expect(policy.isAtLeast('USER', 'ADMIN')).toBe(false)
  })
})

describe('PolicyEngine — addRole', () => {
  let policy: PolicyEngine

  beforeEach(() => {
    policy = new PolicyEngine({ roles: TEST_ROLES })
    policy.addRole({ name: 'VIP', level: 25, permissions: ['vip:access'] })
  })

  it('VIP can vip:access (own permission)', () => {
    expect(policy.can('VIP', 'vip:access')).toBe(true)
  })

  it('VIP can posts:write (inherits from USER at level 20, VIP is 25)', () => {
    expect(policy.can('VIP', 'posts:write')).toBe(true)
  })

  it('addRole returns this (chainable)', () => {
    const result = policy.addRole({ name: 'ANOTHER', level: 5, permissions: [] })
    expect(result).toBe(policy)
  })
})

describe('PolicyEngine — grantTo', () => {
  let policy: PolicyEngine

  beforeEach(() => {
    policy = new PolicyEngine({ roles: TEST_ROLES })
  })

  it('GUEST can extra:perm after grantTo', () => {
    policy.grantTo('GUEST', 'extra:perm')
    expect(policy.can('GUEST', 'extra:perm')).toBe(true)
  })

  it('throws UnknownRoleError for unknown role', () => {
    expect(() => policy.grantTo('PHANTOM', 'posts:read')).toThrow(UnknownRoleError)
  })

  it('throws InvalidPermissionError for invalid permission string', () => {
    expect(() => policy.grantTo('GUEST', 'bad permission!')).toThrow(InvalidPermissionError)
  })

  it('returns this (chainable)', () => {
    const result = policy.grantTo('GUEST', 'extra:perm')
    expect(result).toBe(policy)
  })
})

describe('PolicyEngine — denyFrom', () => {
  let policy: PolicyEngine

  beforeEach(() => {
    policy = new PolicyEngine({ roles: TEST_ROLES })
  })

  it('DEVELOPER cannot admin:panel after denyFrom', () => {
    policy.denyFrom('DEVELOPER', 'admin:panel')
    expect(policy.can('DEVELOPER', 'admin:panel')).toBe(false)
  })

  it('ADMIN can still admin:panel (deny is not inherited by higher roles)', () => {
    policy.denyFrom('DEVELOPER', 'admin:panel')
    expect(policy.can('ADMIN', 'admin:panel')).toBe(true)
  })

  it('returns this (chainable)', () => {
    const result = policy.denyFrom('DEVELOPER', 'admin:panel')
    expect(result).toBe(policy)
  })
})

describe('PolicyEngine — error cases', () => {
  let policy: PolicyEngine

  beforeEach(() => {
    policy = new PolicyEngine({ roles: TEST_ROLES })
  })

  it('can("NONEXISTENT", ...) throws UnknownRoleError', () => {
    expect(() => policy.can('NONEXISTENT', 'posts:read')).toThrow(UnknownRoleError)
  })

  it('can("USER", "bad permission!") throws InvalidPermissionError', () => {
    expect(() => policy.can('USER', 'bad permission!')).toThrow(InvalidPermissionError)
  })
})

describe('PolicyEngine — createContext', () => {
  let policy: PolicyEngine

  beforeEach(() => {
    policy = new PolicyEngine({ roles: TEST_ROLES })
  })

  it('returns an object with can, cannot, assert, isAtLeast', () => {
    const ctx = policy.createContext('USER')
    expect(typeof ctx.can).toBe('function')
    expect(typeof ctx.cannot).toBe('function')
    expect(typeof ctx.assert).toBe('function')
    expect(typeof ctx.isAtLeast).toBe('function')
  })

  it('ctx.can("posts:read") returns true for USER role', () => {
    const ctx = policy.createContext('USER')
    expect(ctx.can('posts:read')).toBe(true)
  })
})

describe('PolicyEngine — revokeFrom', () => {
  let policy: PolicyEngine

  beforeEach(() => {
    policy = new PolicyEngine({ roles: TEST_ROLES })
  })

  it('GUEST cannot posts:read after revokeFrom', () => {
    policy.revokeFrom('GUEST', 'posts:read')
    expect(policy.can('GUEST', 'posts:read')).toBe(false)
  })

  it('revokeFrom is a no-op for a permission the role does not directly own', () => {
    // USER inherits posts:read from GUEST but does not own it directly
    expect(() => policy.revokeFrom('USER', 'posts:read')).not.toThrow()
    // The inherited permission is unaffected — GUEST still has it
    expect(policy.can('USER', 'posts:read')).toBe(true)
  })

  it('throws UnknownRoleError for unknown role', () => {
    expect(() => policy.revokeFrom('PHANTOM', 'posts:read')).toThrow(UnknownRoleError)
  })

  it('throws InvalidPermissionError for invalid permission', () => {
    expect(() => policy.revokeFrom('GUEST', 'bad perm!')).toThrow(InvalidPermissionError)
  })

  it('returns this (chainable)', () => {
    expect(policy.revokeFrom('GUEST', 'posts:read')).toBe(policy)
  })
})

describe('PolicyEngine — removeDeny', () => {
  let policy: PolicyEngine

  beforeEach(() => {
    policy = new PolicyEngine({ roles: TEST_ROLES })
  })

  it('ADMIN can admin:panel again after removeDeny lifts the deny', () => {
    policy.denyFrom('ADMIN', 'admin:panel')
    expect(policy.can('ADMIN', 'admin:panel')).toBe(false)
    policy.removeDeny('ADMIN', 'admin:panel')
    expect(policy.can('ADMIN', 'admin:panel')).toBe(true)
  })

  it('removeDeny is a no-op when no deny exists', () => {
    expect(() => policy.removeDeny('GUEST', 'posts:read')).not.toThrow()
  })

  it('throws UnknownRoleError for unknown role', () => {
    expect(() => policy.removeDeny('PHANTOM', 'posts:read')).toThrow(UnknownRoleError)
  })

  it('returns this (chainable)', () => {
    expect(policy.removeDeny('GUEST', 'posts:read')).toBe(policy)
  })
})

describe('PolicyEngine — assertAll', () => {
  let policy: PolicyEngine

  beforeEach(() => {
    policy = new PolicyEngine({ roles: TEST_ROLES })
  })

  it('does not throw when ADMIN has all permissions', () => {
    expect(() => policy.assertAll('ADMIN', ['users:ban', 'admin:panel'])).not.toThrow()
  })

  it('throws PermissionDeniedError on the first missing permission', () => {
    expect(() => policy.assertAll('USER', ['posts:read', 'users:ban'])).toThrow(PermissionDeniedError)
  })
})

describe('PolicyEngine — assertAny', () => {
  let policy: PolicyEngine

  beforeEach(() => {
    policy = new PolicyEngine({ roles: TEST_ROLES })
  })

  it('does not throw when MODERATOR has at least one permission', () => {
    expect(() => policy.assertAny('MODERATOR', ['users:ban', 'posts:delete'])).not.toThrow()
  })

  it('throws PermissionDeniedError when role has none of the permissions', () => {
    expect(() => policy.assertAny('GUEST', ['users:ban', 'admin:panel'])).toThrow(PermissionDeniedError)
  })
})

describe('PolicyEngine — canWithReason', () => {
  let policy: PolicyEngine

  beforeEach(() => {
    policy = new PolicyEngine({ roles: TEST_ROLES })
  })

  it('returns result:true when permission is granted', () => {
    const res = policy.canWithReason('USER', 'posts:read')
    expect(res.result).toBe(true)
    expect(res.reason).toContain('posts:read')
  })

  it('returns result:false with "No permission" reason when not granted', () => {
    const res = policy.canWithReason('GUEST', 'users:ban')
    expect(res.result).toBe(false)
    expect(res.reason).toContain('No permission')
  })

  it('returns result:false with "explicitly denied" reason when denied', () => {
    policy.denyFrom('USER', 'posts:write')
    const res = policy.canWithReason('USER', 'posts:write')
    expect(res.result).toBe(false)
    expect(res.reason).toContain('explicitly denied')
  })

  it('mentions "inherited" for permissions coming from a lower role', () => {
    const res = policy.canWithReason('MODERATOR', 'posts:read')
    expect(res.result).toBe(true)
    expect(res.reason).toContain('inherited')
  })

  it('mentions wildcard pattern in reason for SUPER_ADMIN', () => {
    const res = policy.canWithReason('SUPER_ADMIN', 'anything:ever')
    expect(res.result).toBe(true)
    expect(res.reason).toContain('*')
  })
})

describe('PolicyEngine — hooks', () => {
  it('onRoleAdd fires when addRole is called', () => {
    const calls: string[] = []
    const policy = new PolicyEngine({
      roles: TEST_ROLES,
      hooks: { onRoleAdd: (r) => calls.push(r.name) },
    })
    policy.addRole({ name: 'VIP', level: 25, permissions: [] })
    expect(calls).toContain('VIP')
  })

  it('onRoleRemove fires when removeRole is called', () => {
    const calls: string[] = []
    const policy = new PolicyEngine({
      roles: TEST_ROLES,
      hooks: { onRoleRemove: (r) => calls.push(r) },
    })
    policy.addRole({ name: 'TEMP', level: 5, permissions: [] })
    policy.removeRole('TEMP')
    expect(calls).toContain('TEMP')
  })

  it('onGrant fires when grantTo is called', () => {
    const calls: Array<[string, string]> = []
    const policy = new PolicyEngine({
      roles: TEST_ROLES,
      hooks: { onGrant: (r, p) => calls.push([r, p]) },
    })
    policy.grantTo('GUEST', 'extra:perm')
    expect(calls).toContainEqual(['GUEST', 'extra:perm'])
  })

  it('onRevoke fires when revokeFrom is called', () => {
    const calls: Array<[string, string]> = []
    const policy = new PolicyEngine({
      roles: TEST_ROLES,
      hooks: { onRevoke: (r, p) => calls.push([r, p]) },
    })
    policy.revokeFrom('GUEST', 'posts:read')
    expect(calls).toContainEqual(['GUEST', 'posts:read'])
  })

  it('onDeny fires when denyFrom is called', () => {
    const calls: Array<[string, string]> = []
    const policy = new PolicyEngine({
      roles: TEST_ROLES,
      hooks: { onDeny: (r, p) => calls.push([r, p]) },
    })
    policy.denyFrom('USER', 'posts:write')
    expect(calls).toContainEqual(['USER', 'posts:write'])
  })

  it('onRemoveDeny fires when removeDeny is called', () => {
    const calls: Array<[string, string]> = []
    const policy = new PolicyEngine({
      roles: TEST_ROLES,
      hooks: { onRemoveDeny: (r, p) => calls.push([r, p]) },
    })
    policy.denyFrom('USER', 'posts:write')
    policy.removeDeny('USER', 'posts:write')
    expect(calls).toContainEqual(['USER', 'posts:write'])
  })
})

describe('PolicyEngine — toJSON / fromJSON', () => {
  it('round-trips roles, denies, and groups', () => {
    const policy = new PolicyEngine({ roles: TEST_ROLES })
    policy.denyFrom('USER', 'posts:write')
    policy.defineGroup('editors', ['posts:publish'])

    const snapshot = policy.toJSON()
    const restored = PolicyEngine.fromJSON(snapshot)

    expect(restored.can('ADMIN', 'users:ban')).toBe(true)
    expect(restored.can('USER', 'posts:write')).toBe(false)
  })

  it('toJSON includes denies', () => {
    const policy = new PolicyEngine({ roles: TEST_ROLES })
    policy.denyFrom('USER', 'posts:write')
    const snap = policy.toJSON()
    expect(snap.denies['USER']).toContain('posts:write')
  })

  it('toJSON includes groups', () => {
    const policy = new PolicyEngine({ roles: TEST_ROLES })
    policy.defineGroup('mygroup', ['foo:bar'])
    const snap = policy.toJSON()
    expect(snap.groups['mygroup']).toContain('foo:bar')
  })

  it('fromJSON restores inherited permissions correctly', () => {
    const policy = new PolicyEngine({ roles: TEST_ROLES })
    const restored = PolicyEngine.fromJSON(policy.toJSON())
    expect(restored.can('MODERATOR', 'posts:read')).toBe(true)
  })
})

describe('PolicyEngine — multi-role createContext', () => {
  let policy: PolicyEngine

  beforeEach(() => {
    policy = new PolicyEngine({ roles: TEST_ROLES })
  })

  it('ctx.can returns true if ANY provided role has the permission', () => {
    const ctx = policy.createContext(['GUEST', 'MODERATOR'])
    expect(ctx.can('users:warn')).toBe(true)
  })

  it('ctx.role is the first role in the array', () => {
    const ctx = policy.createContext(['GUEST', 'USER'])
    expect(ctx.role).toBe('GUEST')
  })

  it('ctx.roles contains all roles', () => {
    const ctx = policy.createContext(['GUEST', 'USER'])
    expect(ctx.roles).toEqual(['GUEST', 'USER'])
  })

  it('ctx.isAtLeast returns true if ANY role meets the threshold', () => {
    const ctx = policy.createContext(['GUEST', 'ADMIN'])
    expect(ctx.isAtLeast('MODERATOR')).toBe(true)
  })

  it('throws UnknownRoleError if any role in the array is unknown', () => {
    expect(() => policy.createContext(['USER', 'PHANTOM'])).toThrow(UnknownRoleError)
  })
})
