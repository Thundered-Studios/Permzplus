import { describe, it, expect } from 'vitest'
import { PolicyEngine } from '../src/policy'
import { accessibleBy, mergeAccessible } from '../src/query'

function makeEngine() {
  return new PolicyEngine({
    roles: [
      { name: 'GUEST', level: 0, permissions: [] },
      { name: 'MEMBER', level: 1, permissions: ['posts:read', 'posts:edit'] },
      { name: 'ADMIN', level: 2, permissions: ['*'] },
    ],
  })
}

describe('accessibleBy', () => {
  it('returns permitted:false when role has no permission', () => {
    const engine = makeEngine()
    const result = accessibleBy(engine, 'GUEST', 'posts:read')
    expect(result.permitted).toBe(false)
    expect(result.unrestricted).toBe(false)
    expect(result.conditions).toHaveLength(0)
  })

  it('returns unrestricted:true when permitted with no conditions', () => {
    const engine = makeEngine()
    const result = accessibleBy(engine, 'MEMBER', 'posts:read')
    expect(result.permitted).toBe(true)
    expect(result.unrestricted).toBe(true)
    expect(result.conditions).toHaveLength(0)
  })

  it('returns object conditions when defineRule used', () => {
    const engine = makeEngine()
    engine.defineRule('MEMBER', 'posts:read', { status: 'published' })
    const result = accessibleBy(engine, 'MEMBER', 'posts:read')
    expect(result.permitted).toBe(true)
    expect(result.unrestricted).toBe(false)
    expect(result.conditions).toHaveLength(1)
    expect(result.conditions[0]).toEqual({ status: 'published' })
  })

  it('excludes function conditions (not serializable)', () => {
    const engine = makeEngine()
    engine.defineRule('MEMBER', 'posts:edit', () => true)
    const result = accessibleBy(engine, 'MEMBER', 'posts:edit')
    // Has permission, has a condition, but it's a function — not in conditions array
    expect(result.permitted).toBe(true)
    expect(result.unrestricted).toBe(false)
    expect(result.conditions).toHaveLength(0)
  })

  it('multiple object conditions all included', () => {
    const engine = makeEngine()
    engine.defineRule('MEMBER', 'posts:read', { status: 'published' })
    engine.defineRule('MEMBER', 'posts:read', { authorId: 'u1' })
    const result = accessibleBy(engine, 'MEMBER', 'posts:read')
    expect(result.conditions).toHaveLength(2)
  })

  it('ADMIN with wildcard — unrestricted', () => {
    const engine = makeEngine()
    const result = accessibleBy(engine, 'ADMIN', 'posts:read')
    expect(result.permitted).toBe(true)
    expect(result.unrestricted).toBe(true)
  })
})

describe('mergeAccessible', () => {
  it('returns not permitted when all results are not permitted', () => {
    const engine = makeEngine()
    const r1 = accessibleBy(engine, 'GUEST', 'posts:read')
    const r2 = accessibleBy(engine, 'GUEST', 'posts:edit')
    const merged = mergeAccessible(r1, r2)
    expect(merged.permitted).toBe(false)
  })

  it('returns unrestricted when any result is unrestricted', () => {
    const engine = makeEngine()
    engine.defineRule('MEMBER', 'posts:read', { status: 'published' })
    const restricted = accessibleBy(engine, 'MEMBER', 'posts:read')
    const unrestricted = accessibleBy(engine, 'ADMIN', 'posts:read')
    const merged = mergeAccessible(restricted, unrestricted)
    expect(merged.unrestricted).toBe(true)
    expect(merged.conditions).toHaveLength(0)
  })

  it('merges conditions from multiple results', () => {
    const engine = makeEngine()
    engine.defineRule('MEMBER', 'posts:read', { status: 'published' })
    engine.defineRule('MEMBER', 'posts:edit', { authorId: 'u1' })
    const r1 = accessibleBy(engine, 'MEMBER', 'posts:read')
    const r2 = accessibleBy(engine, 'MEMBER', 'posts:edit')
    const merged = mergeAccessible(r1, r2)
    expect(merged.permitted).toBe(true)
    expect(merged.conditions).toHaveLength(2)
  })
})
