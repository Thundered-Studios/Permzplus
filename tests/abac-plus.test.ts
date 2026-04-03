import { describe, it, expect } from 'vitest'
import { PolicyEngine } from '../src/policy'

describe('Subject Context (ABAC+) — user attributes in conditionCtx', () => {
  function makeEngine() {
    return new PolicyEngine({
      roles: [{ name: 'MEMBER', level: 1, permissions: ['docs:read', 'docs:edit'] }],
    })
  }

  it('can() passes user context to function conditions via createContext', () => {
    const engine = makeEngine()
    engine.defineRule('MEMBER', 'docs:edit', (doc, ctx) => {
      return (ctx as any)?.user?.dept === (doc as any).dept
    })

    const ctx = engine.createContext('MEMBER', { user: { dept: 'eng' } })
    expect(ctx.can('docs:edit', { dept: 'eng' })).toBe(true)
    expect(ctx.can('docs:edit', { dept: 'hr' })).toBe(false)
  })

  it('can() passes user context directly on engine.can()', () => {
    const engine = makeEngine()
    engine.defineRule('MEMBER', 'docs:read', (doc, ctx) => {
      return (ctx as any)?.user?.clearance >= (doc as any).level
    })

    expect(engine.can('MEMBER', 'docs:read', { level: 2 }, { user: { clearance: 3 } })).toBe(true)
    expect(engine.can('MEMBER', 'docs:read', { level: 5 }, { user: { clearance: 3 } })).toBe(false)
  })

  it('user context is independent from userId', () => {
    const engine = makeEngine()
    engine.defineRule('MEMBER', 'docs:edit', (doc, ctx) => {
      return (ctx as any).userId === (doc as any).owner && (ctx as any).user?.dept === (doc as any).dept
    })

    const ctx = engine.createContext('MEMBER', { userId: 'u1', user: { dept: 'eng' } })
    expect(ctx.can('docs:edit', { owner: 'u1', dept: 'eng' })).toBe(true)
    expect(ctx.can('docs:edit', { owner: 'u1', dept: 'hr' })).toBe(false)
    expect(ctx.can('docs:edit', { owner: 'u2', dept: 'eng' })).toBe(false)
  })
})
