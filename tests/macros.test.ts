import { describe, it, expect } from 'vitest'
import { expandMacros, evalCondition, matchesCondition } from '../src/conditions'
import { PolicyEngine } from '../src/policy'

describe('expandMacros', () => {
  it('resolves a single top-level key', () => {
    expect(expandMacros('{{userId}}', { userId: 'u1' })).toBe('u1')
  })

  it('resolves a nested dot-path', () => {
    expect(expandMacros('{{user.id}}', { user: { id: 'u42' } })).toBe('u42')
  })

  it('preserves the original type for single-macro strings', () => {
    expect(expandMacros('{{count}}', { count: 7 })).toBe(7)
    expect(expandMacros('{{active}}', { active: false })).toBe(false)
  })

  it('coerces to string for mixed templates', () => {
    expect(expandMacros('user-{{userId}}', { userId: 'abc' })).toBe('user-abc')
  })

  it('returns undefined for a missing single-macro path', () => {
    expect(expandMacros('{{missing.path}}', {})).toBeUndefined()
  })

  it('returns empty string for missing path in mixed template', () => {
    expect(expandMacros('id-{{missing}}', {})).toBe('id-')
  })

  it('returns the string unchanged when no macro present', () => {
    expect(expandMacros('plain', { userId: 'u1' })).toBe('plain')
  })
})

describe('matchesCondition — macro expansion', () => {
  it('expands {{user.id}} before comparing', () => {
    const ctx = { user: { id: 'u1' } }
    expect(matchesCondition({ authorId: 'u1' }, { authorId: '{{user.id}}' }, ctx)).toBe(true)
    expect(matchesCondition({ authorId: 'u2' }, { authorId: '{{user.id}}' }, ctx)).toBe(false)
  })

  it('falls back to literal string when no ctx supplied', () => {
    expect(matchesCondition({ authorId: '{{user.id}}' }, { authorId: '{{user.id}}' })).toBe(true)
  })
})

describe('PolicyEngine — possession macros in defineRule object conditions', () => {
  it('authorId: "{{user.id}}" resolves at runtime', () => {
    const engine = new PolicyEngine({
      roles: [{ name: 'MEMBER', level: 1, permissions: ['posts:edit'] }],
    })
    engine.defineRule('MEMBER', 'posts:edit', { authorId: '{{user.id}}' })

    expect(engine.can('MEMBER', 'posts:edit', { authorId: 'u1' }, { user: { id: 'u1' } })).toBe(true)
    expect(engine.can('MEMBER', 'posts:edit', { authorId: 'u2' }, { user: { id: 'u1' } })).toBe(false)
  })

  it('works with createContext user attribute', () => {
    const engine = new PolicyEngine({
      roles: [{ name: 'MEMBER', level: 1, permissions: ['posts:edit'] }],
    })
    engine.defineRule('MEMBER', 'posts:edit', { authorId: '{{user.id}}' })

    const ctx = engine.createContext('MEMBER', { user: { id: 'u5' } })
    expect(ctx.can('posts:edit', { authorId: 'u5' })).toBe(true)
    expect(ctx.can('posts:edit', { authorId: 'u9' })).toBe(false)
  })
})
