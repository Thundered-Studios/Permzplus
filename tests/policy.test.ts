import { describe, it, expect, beforeEach } from 'vitest'
import { PolicyEngine } from '../src/policy'
import { PermissionDeniedError, UnknownRoleError, InvalidPermissionError } from '../src/errors'

describe('PolicyEngine — built-in roles loaded by default', () => {
  let policy: PolicyEngine

  beforeEach(() => {
    policy = new PolicyEngine()
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
      roles: [{ name: 'TESTER', level: 15, permissions: ['tests:run'] }],
    })
  })

  it('TESTER can posts:read (inherited from GUEST at level 0)', () => {
    expect(policy.can('TESTER', 'posts:read')).toBe(true)
  })

  it('TESTER can tests:run (own permission)', () => {
    expect(policy.can('TESTER', 'tests:run')).toBe(true)
  })

  it('TESTER cannot posts:write (USER is level 20, TESTER is 15)', () => {
    expect(policy.can('TESTER', 'posts:write')).toBe(false)
  })
})

describe('PolicyEngine — extra permissions via options.permissions', () => {
  it('GUEST can extra:action when added via options.permissions', () => {
    const policy = new PolicyEngine({ permissions: { GUEST: ['extra:action'] } })
    expect(policy.can('GUEST', 'extra:action')).toBe(true)
  })
})

describe('PolicyEngine — cannot', () => {
  let policy: PolicyEngine

  beforeEach(() => {
    policy = new PolicyEngine()
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
    policy = new PolicyEngine()
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
    policy = new PolicyEngine()
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
    policy = new PolicyEngine()
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
    policy = new PolicyEngine()
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
    policy = new PolicyEngine()
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
    policy = new PolicyEngine()
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
    policy = new PolicyEngine()
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
    policy = new PolicyEngine()
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
