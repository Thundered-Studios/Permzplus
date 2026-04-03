import { describe, it, expect } from 'vitest'
import { PolicyEngine } from '../src/policy'
import { matchesCondition, evalCondition } from '../src/conditions'

// ---------------------------------------------------------------------------
// matchesCondition — MongoDB-style object evaluation
// ---------------------------------------------------------------------------

describe('matchesCondition', () => {
  it('direct field equality', () => {
    expect(matchesCondition({ status: 'published' }, { status: 'published' })).toBe(true)
    expect(matchesCondition({ status: 'draft' }, { status: 'published' })).toBe(false)
  })

  it('$eq', () => {
    expect(matchesCondition({ x: 5 }, { x: { $eq: 5 } })).toBe(true)
    expect(matchesCondition({ x: 4 }, { x: { $eq: 5 } })).toBe(false)
  })

  it('$ne', () => {
    expect(matchesCondition({ x: 3 }, { x: { $ne: 5 } })).toBe(true)
    expect(matchesCondition({ x: 5 }, { x: { $ne: 5 } })).toBe(false)
  })

  it('$gt / $gte / $lt / $lte', () => {
    expect(matchesCondition({ n: 10 }, { n: { $gt: 5 } })).toBe(true)
    expect(matchesCondition({ n: 5 }, { n: { $gt: 5 } })).toBe(false)
    expect(matchesCondition({ n: 5 }, { n: { $gte: 5 } })).toBe(true)
    expect(matchesCondition({ n: 4 }, { n: { $lt: 5 } })).toBe(true)
    expect(matchesCondition({ n: 5 }, { n: { $lt: 5 } })).toBe(false)
    expect(matchesCondition({ n: 5 }, { n: { $lte: 5 } })).toBe(true)
  })

  it('$in / $nin', () => {
    expect(matchesCondition({ role: 'admin' }, { role: { $in: ['admin', 'mod'] } })).toBe(true)
    expect(matchesCondition({ role: 'user' }, { role: { $in: ['admin', 'mod'] } })).toBe(false)
    expect(matchesCondition({ role: 'user' }, { role: { $nin: ['admin', 'mod'] } })).toBe(true)
    expect(matchesCondition({ role: 'admin' }, { role: { $nin: ['admin', 'mod'] } })).toBe(false)
  })

  it('$exists', () => {
    expect(matchesCondition({ a: 1 }, { a: { $exists: true } })).toBe(true)
    expect(matchesCondition({}, { a: { $exists: true } })).toBe(false)
    expect(matchesCondition({}, { a: { $exists: false } })).toBe(true)
    expect(matchesCondition({ a: 1 }, { a: { $exists: false } })).toBe(false)
  })

  it('$and', () => {
    expect(matchesCondition({ x: 5, y: 10 }, { $and: [{ x: 5 }, { y: 10 }] })).toBe(true)
    expect(matchesCondition({ x: 5, y: 9 }, { $and: [{ x: 5 }, { y: 10 }] })).toBe(false)
  })

  it('$or', () => {
    expect(matchesCondition({ status: 'draft' }, { $or: [{ status: 'draft' }, { status: 'published' }] })).toBe(true)
    expect(matchesCondition({ status: 'deleted' }, { $or: [{ status: 'draft' }, { status: 'published' }] })).toBe(false)
  })

  it('$nor', () => {
    expect(matchesCondition({ status: 'deleted' }, { $nor: [{ status: 'draft' }, { status: 'published' }] })).toBe(true)
    expect(matchesCondition({ status: 'draft' }, { $nor: [{ status: 'draft' }, { status: 'published' }] })).toBe(false)
  })

  it('multiple fields — all must match', () => {
    expect(matchesCondition({ a: 1, b: 2 }, { a: 1, b: 2 })).toBe(true)
    expect(matchesCondition({ a: 1, b: 3 }, { a: 1, b: 2 })).toBe(false)
  })

  it('non-object subject returns false', () => {
    expect(evalCondition({ status: 'published' }, 'not-an-object')).toBe(false)
    expect(evalCondition({ status: 'published' }, null)).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// PolicyEngine.defineRule + subject-aware can()
// ---------------------------------------------------------------------------

describe('PolicyEngine — ABAC defineRule', () => {
  function makeEngine() {
    return new PolicyEngine({
      roles: [
        { name: 'MEMBER', level: 1, permissions: ['posts:read', 'posts:edit', 'posts:delete'] },
        { name: 'ADMIN', level: 2, permissions: ['*'] },
      ],
    })
  }

  it('can() without subject ignores conditions (backward compat)', () => {
    const engine = makeEngine()
    engine.defineRule('MEMBER', 'posts:edit', { authorId: 'u1' })
    expect(engine.can('MEMBER', 'posts:edit')).toBe(true)
  })

  it('can() with subject — object condition passes', () => {
    const engine = makeEngine()
    engine.defineRule('MEMBER', 'posts:edit', { authorId: 'u1' })
    expect(engine.can('MEMBER', 'posts:edit', { authorId: 'u1' })).toBe(true)
    expect(engine.can('MEMBER', 'posts:edit', { authorId: 'u2' })).toBe(false)
  })

  it('can() with subject — function condition receives ctx', () => {
    const engine = makeEngine()
    engine.defineRule('MEMBER', 'posts:edit', (post, ctx) => (post as any).authorId === ctx?.userId)
    expect(engine.can('MEMBER', 'posts:edit', { authorId: 'u1' }, { userId: 'u1' })).toBe(true)
    expect(engine.can('MEMBER', 'posts:edit', { authorId: 'u1' }, { userId: 'u2' })).toBe(false)
  })

  it('multiple conditions — ALL must pass (AND semantics)', () => {
    const engine = makeEngine()
    engine.defineRule('MEMBER', 'posts:delete', { status: 'draft' })
    engine.defineRule('MEMBER', 'posts:delete', (post, ctx) => (post as any).authorId === ctx?.userId)
    const ctx = { userId: 'u1' }
    expect(engine.can('MEMBER', 'posts:delete', { status: 'draft', authorId: 'u1' }, ctx)).toBe(true)
    expect(engine.can('MEMBER', 'posts:delete', { status: 'published', authorId: 'u1' }, ctx)).toBe(false)
    expect(engine.can('MEMBER', 'posts:delete', { status: 'draft', authorId: 'u2' }, ctx)).toBe(false)
  })

  it('no conditions — unrestricted (any subject passes)', () => {
    const engine = makeEngine()
    expect(engine.can('MEMBER', 'posts:read', { anything: true })).toBe(true)
  })

  it('cannot() respects subject conditions', () => {
    const engine = makeEngine()
    engine.defineRule('MEMBER', 'posts:edit', { authorId: 'u1' })
    expect(engine.cannot('MEMBER', 'posts:edit', { authorId: 'u2' })).toBe(true)
    expect(engine.cannot('MEMBER', 'posts:edit', { authorId: 'u1' })).toBe(false)
  })

  it('assert() throws when condition fails', () => {
    const engine = makeEngine()
    engine.defineRule('MEMBER', 'posts:edit', { authorId: 'u1' })
    expect(() => engine.assert('MEMBER', 'posts:edit', { authorId: 'u2' })).toThrow()
    expect(() => engine.assert('MEMBER', 'posts:edit', { authorId: 'u1' })).not.toThrow()
  })

  it('safeCan() returns false for unknown role without throwing', () => {
    const engine = makeEngine()
    engine.defineRule('MEMBER', 'posts:edit', { authorId: 'u1' })
    expect(engine.safeCan('UNKNOWN', 'posts:edit', { authorId: 'u1' })).toBe(false)
  })

  it('getConditionsFor returns registered conditions', () => {
    const engine = makeEngine()
    const cond = { authorId: 'u1' }
    engine.defineRule('MEMBER', 'posts:edit', cond)
    expect(engine.getConditionsFor('MEMBER', 'posts:edit')).toHaveLength(1)
    expect(engine.getConditionsFor('MEMBER', 'posts:read')).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// PermissionContext — subject-aware can()
// ---------------------------------------------------------------------------

describe('PermissionContext — subject-aware can()', () => {
  it('passes subject to engine.can()', () => {
    const engine = new PolicyEngine({
      roles: [{ name: 'MEMBER', level: 1, permissions: ['posts:edit'] }],
    })
    engine.defineRule('MEMBER', 'posts:edit', { authorId: 'u1' })

    const ctx = engine.createContext('MEMBER', { userId: 'u1' })
    expect(ctx.can('posts:edit', { authorId: 'u1' })).toBe(true)
    expect(ctx.can('posts:edit', { authorId: 'u2' })).toBe(false)
  })

  it('userId from context opts is passed to function conditions', () => {
    const engine = new PolicyEngine({
      roles: [{ name: 'MEMBER', level: 1, permissions: ['posts:edit'] }],
    })
    engine.defineRule('MEMBER', 'posts:edit', (post, ctx) => (post as any).authorId === ctx?.userId)

    const ctx = engine.createContext('MEMBER', { userId: 'u1' })
    expect(ctx.can('posts:edit', { authorId: 'u1' })).toBe(true)
    expect(ctx.can('posts:edit', { authorId: 'u99' })).toBe(false)
  })

  it('legacy condition callback still works', () => {
    const engine = new PolicyEngine({
      roles: [{ name: 'MEMBER', level: 1, permissions: ['posts:edit'] }],
    })
    const ctx = engine.createContext('MEMBER')
    let flag = true
    expect(ctx.can('posts:edit', () => flag)).toBe(true)
    flag = false
    expect(ctx.can('posts:edit', () => flag)).toBe(false)
  })
})
