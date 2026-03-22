import { describe, it, expect, beforeEach } from 'vitest'
import { PolicyEngine } from '../src/policy'
import { PermissionContext } from '../src/context'
import { PermissionDeniedError } from '../src/errors'

describe('PermissionContext', () => {
  let policy: PolicyEngine
  let ctx: PermissionContext

  beforeEach(() => {
    policy = new PolicyEngine()
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
