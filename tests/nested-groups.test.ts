import { describe, it, expect } from 'vitest'
import { PolicyEngine } from '../src/policy'
import { validate } from '../src/validator'

describe('nested permission groups (@ref syntax)', () => {
  it('resolves one level of nesting: group A references @B', () => {
    const policy = new PolicyEngine({
      roles: [{ name: 'user', level: 1, permissions: [], groups: ['A'] }],
    })
    policy.defineGroup('B', ['posts:read', 'posts:list'])
    policy.defineGroup('A', ['@B'])

    expect(policy.can('user', 'posts:read')).toBe(true)
    expect(policy.can('user', 'posts:list')).toBe(true)
  })

  it('resolves multi-level nesting: A → B → C', () => {
    const policy = new PolicyEngine({
      roles: [{ name: 'admin', level: 10, permissions: [], groups: ['A'] }],
    })
    policy.defineGroup('C', ['settings:read'])
    policy.defineGroup('B', ['@C', 'posts:write'])
    policy.defineGroup('A', ['@B', 'users:read'])

    expect(policy.can('admin', 'settings:read')).toBe(true)
    expect(policy.can('admin', 'posts:write')).toBe(true)
    expect(policy.can('admin', 'users:read')).toBe(true)
  })

  it('throws on direct cycle (A → A)', () => {
    const policy = new PolicyEngine({
      roles: [{ name: 'user', level: 1, permissions: [], groups: ['A'] }],
    })
    policy.defineGroup('A', ['@A'])

    expect(() => policy.can('user', 'posts:read')).toThrow(/Circular group reference/)
  })

  it('throws on indirect cycle (A → B → A)', () => {
    const policy = new PolicyEngine({
      roles: [{ name: 'user', level: 1, permissions: [], groups: ['A'] }],
    })
    policy.defineGroup('A', ['@B'])
    policy.defineGroup('B', ['@A'])

    expect(() => policy.can('user', 'posts:read')).toThrow(/Circular group reference/)
  })

  it('validate() warns when a group references an undefined @ref', () => {
    const groups = {
      A: ['@NonExistent', 'posts:read'],
    }
    const { valid, issues } = validate([], groups)

    expect(valid).toBe(false)
    expect(issues).toHaveLength(1)
    expect(issues[0].type).toBe('undefined_group_ref')
    expect(issues[0].detail).toMatch(/NonExistent/)
  })

  it('validate() passes when all @refs are defined', () => {
    const groups = {
      B: ['posts:read'],
      A: ['@B', 'users:read'],
    }
    const { valid, issues } = validate([], groups)

    expect(valid).toBe(true)
    expect(issues).toHaveLength(0)
  })
})
