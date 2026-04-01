import { describe, it, expect, beforeEach } from 'vitest'
import { PolicyEngine } from '../src/policy'
import { PermissionContext } from '../src/context'
import { PermissionDeniedError } from '../src/errors'

describe('PermissionContext', () => {
  let policy: PolicyEngine
  let ctx: PermissionContext

  beforeEach(() => {
    policy = new PolicyEngine({
      roles: [
        { name: 'USER', level: 0, permissions: ['posts:read'] },
        { name: 'MODERATOR', level: 40, permissions: ['posts:delete'] },
        { name: 'ADMIN', level: 80, permissions: ['users:ban'] },
      ],
    })
    ctx = policy.createContext('MODERATOR', { userId: '42' })
  })

  it('ctx.role equals "MODERATOR"', () => {
    expect(ctx.role).toBe('MODERATOR')
  })

  it('ctx.userId equals "42"', () => {
    expect(ctx.userId).toBe('42')
  })

  it('ctx.can("posts:read") is true', () => {
    expect(ctx.can('posts:read')).toBe(true)
  })

  it('ctx.cannot("users:ban") is true', () => {
    expect(ctx.cannot('users:ban')).toBe(true)
  })

  it('ctx.assert("posts:delete") does not throw', () => {
    expect(() => ctx.assert('posts:delete')).not.toThrow()
  })

  it('ctx.assert("users:ban") throws PermissionDeniedError', () => {
    expect(() => ctx.assert('users:ban')).toThrow(PermissionDeniedError)
  })

  it('ctx.isAtLeast("USER") is true', () => {
    expect(ctx.isAtLeast('USER')).toBe(true)
  })

  it('ctx.isAtLeast("ADMIN") is false', () => {
    expect(ctx.isAtLeast('ADMIN')).toBe(false)
  })
})

describe('PermissionContext — assertAll / assertAny', () => {
  let policy: PolicyEngine
  let ctx: PermissionContext

  beforeEach(() => {
    policy = new PolicyEngine({
      roles: [
        { name: 'USER', level: 0, permissions: ['posts:read'] },
        { name: 'MODERATOR', level: 40, permissions: ['posts:delete', 'users:warn'] },
        { name: 'ADMIN', level: 80, permissions: ['users:ban'] },
      ],
    })
    ctx = policy.createContext('MODERATOR')
  })

  it('assertAll does not throw when role has all permissions', () => {
    expect(() => ctx.assertAll(['posts:read', 'posts:delete'])).not.toThrow()
  })

  it('assertAll throws PermissionDeniedError when a permission is missing', () => {
    expect(() => ctx.assertAll(['posts:read', 'users:ban'])).toThrow(PermissionDeniedError)
  })

  it('assertAny does not throw when role has at least one permission', () => {
    expect(() => ctx.assertAny(['users:ban', 'posts:delete'])).not.toThrow()
  })

  it('assertAny throws PermissionDeniedError when role has none', () => {
    expect(() => ctx.assertAny(['users:ban', 'admin:panel'])).toThrow(PermissionDeniedError)
  })
})

describe('PermissionContext — canWithReason', () => {
  let policy: PolicyEngine

  beforeEach(() => {
    policy = new PolicyEngine({
      roles: [
        { name: 'USER', level: 0, permissions: ['posts:read'] },
        { name: 'ADMIN', level: 80, permissions: ['users:ban'] },
      ],
    })
  })

  it('returns result:true with a reason for a granted permission', () => {
    const ctx = policy.createContext('ADMIN')
    const res = ctx.canWithReason('posts:read')
    expect(res.result).toBe(true)
    expect(typeof res.reason).toBe('string')
  })

  it('returns result:false with a reason for a missing permission', () => {
    const ctx = policy.createContext('USER')
    const res = ctx.canWithReason('users:ban')
    expect(res.result).toBe(false)
    expect(res.reason).toContain('No permission')
  })
})

describe('PermissionContext — multi-role', () => {
  let policy: PolicyEngine

  beforeEach(() => {
    policy = new PolicyEngine({
      roles: [
        { name: 'VIEWER', level: 0, permissions: ['posts:read'] },
        { name: 'EDITOR', level: 20, permissions: ['posts:write'] },
        { name: 'ADMIN', level: 80, permissions: ['users:ban'] },
      ],
    })
  })

  it('can returns true if ANY role has the permission', () => {
    const ctx = policy.createContext(['VIEWER', 'ADMIN'])
    expect(ctx.can('users:ban')).toBe(true)
  })

  it('cannot returns true only when ALL roles lack the permission', () => {
    const ctx = policy.createContext(['VIEWER', 'EDITOR'])
    expect(ctx.cannot('users:ban')).toBe(true)
  })

  it('canWithReason returns passing reason for first matching role', () => {
    const ctx = policy.createContext(['VIEWER', 'ADMIN'])
    const res = ctx.canWithReason('users:ban')
    expect(res.result).toBe(true)
  })

  it('isAtLeast returns true if ANY role meets threshold', () => {
    const ctx = policy.createContext(['VIEWER', 'ADMIN'])
    expect(ctx.isAtLeast('EDITOR')).toBe(true)
  })
})
