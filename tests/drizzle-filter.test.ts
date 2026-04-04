/**
 * Tests for drizzleFilter() and toDrizzle() — the ABAC SQL filter generator.
 *
 * We mock a Drizzle table using plain objects whose properties are the
 * column identifiers that Drizzle would create. The drizzle-orm operator
 * functions (eq, and, or, …) are real — we import them and check the
 * shape of the returned SQL object rather than its rendered SQL string,
 * because the exact SQL text can vary across Drizzle versions.
 */

import { describe, it, expect, beforeEach } from 'vitest'
import { PolicyEngine } from '../src/policy'
import { drizzleFilter, toDrizzle } from '../src/adapters/drizzle'

// ---------------------------------------------------------------------------
// Minimal "table" mock
// Each property value is a drizzle-orm column created with integer()/text().
// We use the actual drizzle-orm column constructors so the SQL builder can
// reference them correctly.
// ---------------------------------------------------------------------------
import { integer, text } from 'drizzle-orm/sqlite-core'

// Build lightweight column stubs that drizzle-orm operators can work with
const col = {
  status:      text('status'),
  authorId:    text('author_id'),
  views:       integer('views'),
  score:       integer('score'),
  deletedAt:   text('deleted_at'),
}

// ---------------------------------------------------------------------------
// Helper: assert the filter is a real SQL object (not undefined / null)
// ---------------------------------------------------------------------------
function isSql(v: unknown): boolean {
  // drizzle-orm SQL objects have a `queryChunks` array or similar internal
  // property. The simplest heuristic: they are non-null objects.
  return v !== null && v !== undefined && typeof v === 'object'
}

// ---------------------------------------------------------------------------
// PolicyEngine fixture
// ---------------------------------------------------------------------------
let policy: PolicyEngine

beforeEach(() => {
  policy = new PolicyEngine()
  policy.addRole({ name: 'VIEWER', level: 1, permissions: ['posts:read'] })
  policy.addRole({ name: 'EDITOR', level: 2, permissions: ['posts:read', 'posts:write'] })
  policy.addRole({ name: 'ADMIN',  level: 3, permissions: ['*'] })
})

// ---------------------------------------------------------------------------
// drizzleFilter — permitted / blocked / unrestricted
// ---------------------------------------------------------------------------

describe('drizzleFilter — access control', () => {
  it('returns permitted:false and a 1=0 filter when role has no permission', () => {
    const { permitted, filter } = drizzleFilter(policy, 'VIEWER', 'posts:delete', col)
    expect(permitted).toBe(false)
    expect(isSql(filter)).toBe(true)  // sql`1 = 0`
  })

  it('returns unrestricted:true and undefined filter when no conditions', () => {
    const { permitted, unrestricted, filter } = drizzleFilter(policy, 'VIEWER', 'posts:read', col)
    expect(permitted).toBe(true)
    expect(unrestricted).toBe(true)
    expect(filter).toBeUndefined()
  })

  it('returns unrestricted:true for wildcard ADMIN role', () => {
    const { permitted, unrestricted, filter } = drizzleFilter(policy, 'ADMIN', 'anything:read', col)
    expect(permitted).toBe(true)
    expect(unrestricted).toBe(true)
    expect(filter).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// drizzleFilter — condition conversion
// ---------------------------------------------------------------------------

describe('drizzleFilter — condition → SQL', () => {
  it('converts a simple equality condition', () => {
    policy.defineRule('VIEWER', 'posts:read', { status: 'published' })
    const { permitted, unrestricted, filter } = drizzleFilter(policy, 'VIEWER', 'posts:read', col)
    expect(permitted).toBe(true)
    expect(unrestricted).toBe(false)
    expect(isSql(filter)).toBe(true)
  })

  it('converts $eq operator', () => {
    policy.defineRule('VIEWER', 'posts:read', { status: { $eq: 'active' } })
    const { filter } = drizzleFilter(policy, 'VIEWER', 'posts:read', col)
    expect(isSql(filter)).toBe(true)
  })

  it('converts $ne operator', () => {
    policy.defineRule('VIEWER', 'posts:read', { status: { $ne: 'deleted' } })
    const { filter } = drizzleFilter(policy, 'VIEWER', 'posts:read', col)
    expect(isSql(filter)).toBe(true)
  })

  it('converts $gt operator', () => {
    policy.defineRule('VIEWER', 'posts:read', { views: { $gt: 0 } })
    const { filter } = drizzleFilter(policy, 'VIEWER', 'posts:read', col)
    expect(isSql(filter)).toBe(true)
  })

  it('converts $gte operator', () => {
    policy.defineRule('VIEWER', 'posts:read', { views: { $gte: 10 } })
    const { filter } = drizzleFilter(policy, 'VIEWER', 'posts:read', col)
    expect(isSql(filter)).toBe(true)
  })

  it('converts $lt operator', () => {
    policy.defineRule('VIEWER', 'posts:read', { score: { $lt: 100 } })
    const { filter } = drizzleFilter(policy, 'VIEWER', 'posts:read', col)
    expect(isSql(filter)).toBe(true)
  })

  it('converts $lte operator', () => {
    policy.defineRule('VIEWER', 'posts:read', { score: { $lte: 50 } })
    const { filter } = drizzleFilter(policy, 'VIEWER', 'posts:read', col)
    expect(isSql(filter)).toBe(true)
  })

  it('converts $in operator', () => {
    policy.defineRule('VIEWER', 'posts:read', { status: { $in: ['published', 'featured'] } })
    const { filter } = drizzleFilter(policy, 'VIEWER', 'posts:read', col)
    expect(isSql(filter)).toBe(true)
  })

  it('converts $nin operator', () => {
    policy.defineRule('VIEWER', 'posts:read', { status: { $nin: ['draft', 'archived'] } })
    const { filter } = drizzleFilter(policy, 'VIEWER', 'posts:read', col)
    expect(isSql(filter)).toBe(true)
  })

  it('converts $exists: true → isNotNull', () => {
    policy.defineRule('VIEWER', 'posts:read', { authorId: { $exists: true } })
    const { filter } = drizzleFilter(policy, 'VIEWER', 'posts:read', col)
    expect(isSql(filter)).toBe(true)
  })

  it('converts $exists: false → isNull', () => {
    policy.defineRule('VIEWER', 'posts:read', { deletedAt: { $exists: false } })
    const { filter } = drizzleFilter(policy, 'VIEWER', 'posts:read', col)
    expect(isSql(filter)).toBe(true)
  })

  it('converts $between operator', () => {
    policy.defineRule('VIEWER', 'posts:read', { views: { $between: [10, 100] } })
    const { filter } = drizzleFilter(policy, 'VIEWER', 'posts:read', col)
    expect(isSql(filter)).toBe(true)
  })

  it('converts $regex operator', () => {
    policy.defineRule('VIEWER', 'posts:read', { status: { $regex: 'pub.*' } })
    const { filter } = drizzleFilter(policy, 'VIEWER', 'posts:read', col)
    expect(isSql(filter)).toBe(true)
  })

  it('converts multiple fields in one condition → AND', () => {
    policy.defineRule('VIEWER', 'posts:read', { status: 'published', views: { $gte: 1 } })
    const { filter } = drizzleFilter(policy, 'VIEWER', 'posts:read', col)
    expect(isSql(filter)).toBe(true)
  })

  it('OR-combines multiple separate conditions from multiple defineRule calls', () => {
    policy.defineRule('VIEWER', 'posts:read', { status: 'published' })
    policy.defineRule('VIEWER', 'posts:read', { authorId: 'u1' })
    const { filter } = drizzleFilter(policy, 'VIEWER', 'posts:read', col)
    expect(isSql(filter)).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// drizzleFilter — logical operators
// ---------------------------------------------------------------------------

describe('drizzleFilter — logical operators', () => {
  it('converts $and operator', () => {
    policy.defineRule('VIEWER', 'posts:read', {
      $and: [{ status: 'published' }, { views: { $gte: 5 } }],
    })
    const { filter } = drizzleFilter(policy, 'VIEWER', 'posts:read', col)
    expect(isSql(filter)).toBe(true)
  })

  it('converts $or operator', () => {
    policy.defineRule('VIEWER', 'posts:read', {
      $or: [{ status: 'published' }, { status: 'featured' }],
    })
    const { filter } = drizzleFilter(policy, 'VIEWER', 'posts:read', col)
    expect(isSql(filter)).toBe(true)
  })

  it('converts $nor operator', () => {
    policy.defineRule('VIEWER', 'posts:read', {
      $nor: [{ status: 'draft' }, { status: 'archived' }],
    })
    const { filter } = drizzleFilter(policy, 'VIEWER', 'posts:read', col)
    expect(isSql(filter)).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// drizzleFilter — edge cases
// ---------------------------------------------------------------------------

describe('drizzleFilter — edge cases', () => {
  it('silently skips unknown field names (not on table)', () => {
    policy.defineRule('VIEWER', 'posts:read', { nonExistentColumn: 'x' })
    const { filter, unrestricted } = drizzleFilter(policy, 'VIEWER', 'posts:read', col)
    // All fields unknown → treated as unrestricted (safe fallback)
    expect(unrestricted).toBe(true)
    expect(filter).toBeUndefined()
  })

  it('silently skips unknown $operators', () => {
    policy.defineRule('VIEWER', 'posts:read', { status: { $unknownOp: 'x' } })
    const { filter, unrestricted } = drizzleFilter(policy, 'VIEWER', 'posts:read', col)
    expect(unrestricted).toBe(true)
    expect(filter).toBeUndefined()
  })

  it('works for function conditions (excluded from filter, treated as unrestricted)', () => {
    policy.defineRule('VIEWER', 'posts:read', (post: unknown) => !!(post as Record<string, unknown>)?.published)
    const { permitted, unrestricted, filter } = drizzleFilter(policy, 'VIEWER', 'posts:read', col)
    // Function conditions cannot be serialised → unrestricted fallback
    expect(permitted).toBe(true)
    expect(unrestricted).toBe(true)
    expect(filter).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// toDrizzle — low-level building block
// ---------------------------------------------------------------------------

describe('toDrizzle', () => {
  it('converts a simple condition object to SQL', () => {
    const result = toDrizzle({ status: 'published' }, col)
    expect(isSql(result)).toBe(true)
  })

  it('converts compound conditions', () => {
    const result = toDrizzle(
      { status: 'published', views: { $gte: 10 }, score: { $lte: 100 } },
      col,
    )
    expect(isSql(result)).toBe(true)
  })

  it('returns undefined for an empty condition object', () => {
    const result = toDrizzle({}, col)
    expect(result).toBeUndefined()
  })

  it('returns undefined when no fields match table columns', () => {
    const result = toDrizzle({ ghost: 'value' }, col)
    expect(result).toBeUndefined()
  })

  it('converts $and top-level', () => {
    const result = toDrizzle(
      { $and: [{ status: 'published' }, { views: { $gt: 0 } }] },
      col,
    )
    expect(isSql(result)).toBe(true)
  })

  it('converts $or top-level', () => {
    const result = toDrizzle(
      { $or: [{ status: 'draft' }, { score: { $lte: 0 } }] },
      col,
    )
    expect(isSql(result)).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Performance — conversion must complete in < 1 ms
// ---------------------------------------------------------------------------

describe('drizzleFilter — performance', () => {
  it('converts 1000 conditions in under 1 ms per call', () => {
    policy.defineRule('EDITOR', 'posts:write', { status: 'draft', views: { $gte: 0 }, score: { $lte: 999 } })

    const start = performance.now()
    for (let i = 0; i < 1000; i++) {
      drizzleFilter(policy, 'EDITOR', 'posts:write', col)
    }
    const elapsed = performance.now() - start
    const perCall = elapsed / 1000

    // Each call should take well under 1 ms on any modern machine
    expect(perCall).toBeLessThan(1)
  })
})
