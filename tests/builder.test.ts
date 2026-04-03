import { describe, it, expect } from 'vitest'
import { createPermz } from '../src'
import { PolicyEngine } from '../src/policy'
import type { PolicySnapshot } from '../src/types'

// ---------------------------------------------------------------------------
// createPermz() — fluent builder unit tests
// ---------------------------------------------------------------------------

describe('createPermz() — snapshot shape', () => {
  it('produces the exact PolicySnapshot that a hand-written object would', () => {
    const built = createPermz({ name: 'EDITOR', level: 20 })
      .can('read', 'posts')
      .can('write', 'posts')
      .build()

    const manual: PolicySnapshot = {
      roles: [{ name: 'EDITOR', level: 20, permissions: ['posts:read', 'posts:write'] }],
      denies: {},
      groups: {},
    }

    expect(built).toEqual(manual)
  })

  it('populates denies when .cannot() is used', () => {
    const built = createPermz({ name: 'MEMBER', level: 10 })
      .can('read', 'posts')
      .cannot('delete', 'posts')
      .build()

    const manual: PolicySnapshot = {
      roles: [{ name: 'MEMBER', level: 10, permissions: ['posts:read'] }],
      denies: { MEMBER: ['posts:delete'] },
      groups: {},
    }

    expect(built).toEqual(manual)
  })

  it('omits the denies key when there are no .cannot() calls', () => {
    const { denies } = createPermz({ name: 'GUEST', level: 0 })
      .can('read', 'posts')
      .build()

    expect(denies).toEqual({})
  })

  it('preserves insertion order for permissions', () => {
    const { roles } = createPermz({ name: 'MOD', level: 30 })
      .can('read', 'posts')
      .can('delete', 'posts')
      .can('ban', 'users')
      .build()

    expect(roles[0].permissions).toEqual(['posts:read', 'posts:delete', 'users:ban'])
  })

  it('preserves insertion order for denies', () => {
    const { denies } = createPermz({ name: 'MOD', level: 30 })
      .cannot('edit', 'billing')
      .cannot('delete', 'billing')
      .build()

    expect(denies['MOD']).toEqual(['billing:edit', 'billing:delete'])
  })
})

describe('createPermz() — chaining', () => {
  it('.can() returns the same builder instance', () => {
    const b = createPermz({ name: 'X', level: 0 })
    expect(b.can('read', 'posts')).toBe(b)
  })

  it('.cannot() returns the same builder instance', () => {
    const b = createPermz({ name: 'X', level: 0 })
    expect(b.cannot('delete', 'posts')).toBe(b)
  })

  it('supports a fully chained one-liner', () => {
    expect(() =>
      createPermz({ name: 'ADMIN', level: 100 })
        .can('manage', 'users')
        .cannot('delete', 'audit')
        .build(),
    ).not.toThrow()
  })
})

describe('createPermz() — PolicyEngine integration', () => {
  it('snapshot is accepted by PolicyEngine.fromJSON and resolver works correctly', () => {
    const snapshot = createPermz({ name: 'WRITER', level: 20 })
      .can('read', 'posts')
      .can('write', 'posts')
      .cannot('delete', 'posts')
      .build()

    const policy = PolicyEngine.fromJSON(snapshot)

    expect(policy.can('WRITER', 'posts:read')).toBe(true)
    expect(policy.can('WRITER', 'posts:write')).toBe(true)
    expect(policy.cannot('WRITER', 'posts:delete')).toBe(true)
  })

  it('produced snapshot is identical to the equivalent manually built snapshot', () => {
    const manual: PolicySnapshot = {
      roles: [{ name: 'SUPPORT', level: 15, permissions: ['tickets:read', 'tickets:reply'] }],
      denies: { SUPPORT: ['tickets:close'] },
      groups: {},
    }

    const built = createPermz({ name: 'SUPPORT', level: 15 })
      .can('read', 'tickets')
      .can('reply', 'tickets')
      .cannot('close', 'tickets')
      .build()

    expect(built).toEqual(manual)
  })
})

describe('createPermz() — type-safe generics', () => {
  it('accepts narrowed Action/Resource generics without runtime errors', () => {
    type Action = 'read' | 'write' | 'delete'
    type Resource = 'posts' | 'comments'

    const snapshot = createPermz<Action, Resource>({ name: 'TYPED', level: 5 })
      .can('read', 'posts')
      .can('write', 'comments')
      .cannot('delete', 'posts')
      .build()

    expect(snapshot.roles[0].permissions).toContain('posts:read')
    expect(snapshot.roles[0].permissions).toContain('comments:write')
    expect(snapshot.denies['TYPED']).toContain('posts:delete')
  })
})
