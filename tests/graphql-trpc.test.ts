import { describe, it, expect } from 'vitest'
import { withPermission, withPermissions, createPermissionRule } from '../src/adapters/graphql'
import { trpcPermission, trpcPermissions, trpcCanCheck } from '../src/adapters/trpc'
import { PolicyEngine } from '../src/policy'
import { PermissionDeniedError } from '../src/errors'

function makeEngine() {
  return new PolicyEngine({
    roles: [
      { name: 'USER', level: 0, permissions: ['posts:read'] },
      { name: 'ADMIN', level: 80, permissions: ['posts:read', 'posts:write', 'posts:delete'] },
    ],
  })
}

// tRPC mock: middlewareFn simply returns the inner function so tests can call it directly
const mockMiddlewareFn = (fn: (opts: { ctx: unknown; next: (opts?: unknown) => unknown }) => unknown) => fn

describe('GraphQL adapter', () => {
  describe('withPermission', () => {
    it('calls resolver when role has permission', () => {
      const engine = makeEngine()
      const resolver = () => 'result'
      const wrapped = withPermission(engine, 'posts:read', resolver)
      const result = wrapped(null, {}, { role: 'USER' }, null)
      expect(result).toBe('result')
    })

    it('throws PermissionDeniedError when role lacks permission', () => {
      const engine = makeEngine()
      const resolver = () => 'result'
      const wrapped = withPermission(engine, 'posts:write', resolver)
      expect(() => wrapped(null, {}, { role: 'USER' }, null)).toThrow(PermissionDeniedError)
    })

    it('throws PermissionDeniedError when no role in context', () => {
      const engine = makeEngine()
      const resolver = () => 'result'
      const wrapped = withPermission(engine, 'posts:read', resolver)
      expect(() => wrapped(null, {}, {}, null)).toThrow(PermissionDeniedError)
    })

    it('extracts role from context.user.role', () => {
      const engine = makeEngine()
      const resolver = () => 'result'
      const wrapped = withPermission(engine, 'posts:read', resolver)
      const result = wrapped(null, {}, { user: { role: 'USER' } }, null)
      expect(result).toBe('result')
    })
  })

  describe('withPermissions', () => {
    it('calls resolver when role has all permissions', () => {
      const engine = makeEngine()
      const resolver = () => 'ok'
      const wrapped = withPermissions(engine, ['posts:read', 'posts:write'], resolver)
      const result = wrapped(null, {}, { role: 'ADMIN' }, null)
      expect(result).toBe('ok')
    })

    it('throws PermissionDeniedError when role lacks one of the permissions', () => {
      const engine = makeEngine()
      const resolver = () => 'ok'
      const wrapped = withPermissions(engine, ['posts:read', 'posts:write'], resolver)
      expect(() => wrapped(null, {}, { role: 'USER' }, null)).toThrow(PermissionDeniedError)
    })

    it('throws PermissionDeniedError when no role in context', () => {
      const engine = makeEngine()
      const resolver = () => 'ok'
      const wrapped = withPermissions(engine, ['posts:read'], resolver)
      expect(() => wrapped(null, {}, {}, null)).toThrow(PermissionDeniedError)
    })
  })

  describe('createPermissionRule', () => {
    it('returns true when role has permission', () => {
      const engine = makeEngine()
      const rule = createPermissionRule(engine, 'posts:read')
      expect(rule(null, {}, { role: 'USER' })).toBe(true)
    })

    it('returns false when role lacks permission', () => {
      const engine = makeEngine()
      const rule = createPermissionRule(engine, 'posts:write')
      expect(rule(null, {}, { role: 'USER' })).toBe(false)
    })

    it('returns false when no role in context', () => {
      const engine = makeEngine()
      const rule = createPermissionRule(engine, 'posts:read')
      expect(rule(null, {}, {})).toBe(false)
    })

    it('does not throw for unknown roles', () => {
      const engine = makeEngine()
      const rule = createPermissionRule(engine, 'posts:read')
      expect(() => rule(null, {}, { role: 'UNKNOWN' })).not.toThrow()
    })
  })
})

describe('tRPC adapter', () => {
  describe('trpcPermission', () => {
    it('calls next() when role has permission', () => {
      const engine = makeEngine()
      const middleware = trpcPermission(mockMiddlewareFn, engine, 'posts:read') as (opts: {
        ctx: unknown
        next: () => unknown
      }) => unknown
      let called = false
      middleware({ ctx: { role: 'USER' }, next: () => { called = true; return true } })
      expect(called).toBe(true)
    })

    it('throws PermissionDeniedError when role lacks permission', () => {
      const engine = makeEngine()
      const middleware = trpcPermission(mockMiddlewareFn, engine, 'posts:write') as (opts: {
        ctx: unknown
        next: () => unknown
      }) => unknown
      expect(() => middleware({ ctx: { role: 'USER' }, next: () => {} })).toThrow(PermissionDeniedError)
    })

    it('throws PermissionDeniedError when no role in context', () => {
      const engine = makeEngine()
      const middleware = trpcPermission(mockMiddlewareFn, engine, 'posts:read') as (opts: {
        ctx: unknown
        next: () => unknown
      }) => unknown
      expect(() => middleware({ ctx: {}, next: () => {} })).toThrow(PermissionDeniedError)
    })

    it('extracts role from ctx.user.role', () => {
      const engine = makeEngine()
      const middleware = trpcPermission(mockMiddlewareFn, engine, 'posts:read') as (opts: {
        ctx: unknown
        next: () => unknown
      }) => unknown
      let called = false
      middleware({ ctx: { user: { role: 'USER' } }, next: () => { called = true; return true } })
      expect(called).toBe(true)
    })
  })

  describe('trpcPermissions', () => {
    it('calls next() when role has all permissions', () => {
      const engine = makeEngine()
      const middleware = trpcPermissions(mockMiddlewareFn, engine, ['posts:read', 'posts:write']) as (opts: {
        ctx: unknown
        next: () => unknown
      }) => unknown
      let called = false
      middleware({ ctx: { role: 'ADMIN' }, next: () => { called = true; return true } })
      expect(called).toBe(true)
    })

    it('throws PermissionDeniedError when role lacks one permission', () => {
      const engine = makeEngine()
      const middleware = trpcPermissions(mockMiddlewareFn, engine, ['posts:read', 'posts:write']) as (opts: {
        ctx: unknown
        next: () => unknown
      }) => unknown
      expect(() => middleware({ ctx: { role: 'USER' }, next: () => {} })).toThrow(PermissionDeniedError)
    })

    it('throws PermissionDeniedError when no role in context', () => {
      const engine = makeEngine()
      const middleware = trpcPermissions(mockMiddlewareFn, engine, ['posts:read']) as (opts: {
        ctx: unknown
        next: () => unknown
      }) => unknown
      expect(() => middleware({ ctx: {}, next: () => {} })).toThrow(PermissionDeniedError)
    })
  })

  describe('trpcCanCheck', () => {
    it('returns true when role has permission', () => {
      const engine = makeEngine()
      const check = trpcCanCheck(engine, 'posts:read')
      expect(check({ role: 'USER' })).toBe(true)
    })

    it('returns false when role lacks permission', () => {
      const engine = makeEngine()
      const check = trpcCanCheck(engine, 'posts:write')
      expect(check({ role: 'USER' })).toBe(false)
    })

    it('returns false when no role in context', () => {
      const engine = makeEngine()
      const check = trpcCanCheck(engine, 'posts:read')
      expect(check({})).toBe(false)
    })

    it('does not throw for unknown roles', () => {
      const engine = makeEngine()
      const check = trpcCanCheck(engine, 'posts:read')
      expect(() => check({ role: 'UNKNOWN' })).not.toThrow()
    })
  })
})
