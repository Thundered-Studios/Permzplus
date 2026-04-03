import { describe, it, expect, beforeEach } from 'vitest'
import { InMemoryAuditLogger } from '../src/audit'
import type { AuditEvent } from '../src/types'

function makeEvent(overrides: Partial<AuditEvent>): AuditEvent {
  return {
    action: 'role.add',
    timestamp: new Date('2024-01-01T00:00:00Z'),
    ...overrides,
  }
}

describe('InMemoryAuditLogger.query()', () => {
  let audit: InMemoryAuditLogger

  beforeEach(() => {
    audit = new InMemoryAuditLogger()

    audit.log(makeEvent({ action: 'role.add', role: 'ADMIN', userId: 'u1', tenantId: 't1', timestamp: new Date('2024-01-01T10:00:00Z') }))
    audit.log(makeEvent({ action: 'role.add', role: 'EDITOR', userId: 'u2', tenantId: 't2', timestamp: new Date('2024-01-02T10:00:00Z') }))
    audit.log(makeEvent({ action: 'user.assignRole', role: 'ADMIN', userId: 'u1', tenantId: 't1', timestamp: new Date('2024-01-03T10:00:00Z') }))
    audit.log(makeEvent({ action: 'user.assignRole', role: 'VIEWER', userId: 'u3', tenantId: 't2', timestamp: new Date('2024-01-04T10:00:00Z') }))
    audit.log(makeEvent({ action: 'role.remove', role: 'EDITOR', userId: 'u2', tenantId: 't1', timestamp: new Date('2024-01-05T10:00:00Z') }))
  })

  it('returns all events when query is empty', () => {
    expect(audit.query({})).toHaveLength(5)
  })

  it('filters by single action', () => {
    const results = audit.query({ action: 'role.add' })
    expect(results).toHaveLength(2)
    expect(results.every((e) => e.action === 'role.add')).toBe(true)
  })

  it('filters by multiple actions', () => {
    const results = audit.query({ action: ['role.add', 'role.remove'] })
    expect(results).toHaveLength(3)
    expect(results.every((e) => e.action === 'role.add' || e.action === 'role.remove')).toBe(true)
  })

  it('filters by userId', () => {
    const results = audit.query({ userId: 'u1' })
    expect(results).toHaveLength(2)
    expect(results.every((e) => e.userId === 'u1')).toBe(true)
  })

  it('filters by role', () => {
    const results = audit.query({ role: 'ADMIN' })
    expect(results).toHaveLength(2)
    expect(results.every((e) => e.role === 'ADMIN')).toBe(true)
  })

  it('filters by tenantId', () => {
    const results = audit.query({ tenantId: 't2' })
    expect(results).toHaveLength(2)
    expect(results.every((e) => e.tenantId === 't2')).toBe(true)
  })

  it('filters by since date (inclusive)', () => {
    const results = audit.query({ since: new Date('2024-01-03T10:00:00Z') })
    expect(results).toHaveLength(3)
    expect(results[0].action).toBe('user.assignRole')
  })

  it('filters by until date (inclusive)', () => {
    const results = audit.query({ until: new Date('2024-01-02T10:00:00Z') })
    expect(results).toHaveLength(2)
  })

  it('filters by since and until range', () => {
    const results = audit.query({
      since: new Date('2024-01-02T10:00:00Z'),
      until: new Date('2024-01-03T10:00:00Z'),
    })
    expect(results).toHaveLength(2)
  })

  it('returns results in ascending order by default (oldest first)', () => {
    const results = audit.query({})
    for (let i = 1; i < results.length; i++) {
      expect(results[i].timestamp.getTime()).toBeGreaterThanOrEqual(results[i - 1].timestamp.getTime())
    }
  })

  it('returns results in descending order when order is desc', () => {
    const results = audit.query({ order: 'desc' })
    for (let i = 1; i < results.length; i++) {
      expect(results[i].timestamp.getTime()).toBeLessThanOrEqual(results[i - 1].timestamp.getTime())
    }
  })

  it('applies limit after filtering', () => {
    const results = audit.query({ limit: 2 })
    expect(results).toHaveLength(2)
  })

  it('applies limit with desc order (most recent N events)', () => {
    const results = audit.query({ order: 'desc', limit: 2 })
    expect(results).toHaveLength(2)
    expect(results[0].timestamp.getTime()).toBeGreaterThan(results[1].timestamp.getTime())
  })

  it('combines multiple filters with AND semantics', () => {
    const results = audit.query({ action: 'user.assignRole', userId: 'u1' })
    expect(results).toHaveLength(1)
    expect(results[0].role).toBe('ADMIN')
  })

  it('returns empty array when no events match', () => {
    const results = audit.query({ userId: 'nonexistent' })
    expect(results).toHaveLength(0)
  })
})

describe('InMemoryAuditLogger convenience methods', () => {
  let audit: InMemoryAuditLogger

  beforeEach(() => {
    audit = new InMemoryAuditLogger()

    audit.log(makeEvent({ action: 'role.add', role: 'ADMIN', userId: 'u1', tenantId: 't1', timestamp: new Date('2024-01-01T10:00:00Z') }))
    audit.log(makeEvent({ action: 'user.assignRole', role: 'EDITOR', userId: 'u2', tenantId: 't2', timestamp: new Date('2024-01-03T10:00:00Z') }))
    audit.log(makeEvent({ action: 'role.remove', role: 'VIEWER', userId: 'u1', tenantId: 't1', timestamp: new Date('2024-01-05T10:00:00Z') }))
  })

  it('since() returns events at or after the given date', () => {
    const results = audit.since(new Date('2024-01-03T10:00:00Z'))
    expect(results).toHaveLength(2)
  })

  it('forUser() returns events for the given userId', () => {
    const results = audit.forUser('u1')
    expect(results).toHaveLength(2)
    expect(results.every((e) => e.userId === 'u1')).toBe(true)
  })

  it('forRole() returns events for the given role', () => {
    const results = audit.forRole('EDITOR')
    expect(results).toHaveLength(1)
    expect(results[0].action).toBe('user.assignRole')
  })

  it('forTenant() returns events for the given tenantId', () => {
    const results = audit.forTenant('t2')
    expect(results).toHaveLength(1)
    expect(results[0].userId).toBe('u2')
  })
})
