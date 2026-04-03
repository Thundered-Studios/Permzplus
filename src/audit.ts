import type { AuditAction, AuditEvent, AuditLogger } from './types'

export interface AuditQuery {
  /** Filter by one or more action types. */
  action?: AuditAction | AuditAction[]
  /** Only events for this userId. */
  userId?: string
  /** Only events for this role. */
  role?: string
  /** Only events for this tenantId. */
  tenantId?: string
  /** Only events at or after this date. */
  since?: Date
  /** Only events at or before this date. */
  until?: Date
  /** Limit result count (applied after filtering). */
  limit?: number
  /** Sort order. Default: 'asc' (oldest first). */
  order?: 'asc' | 'desc'
}

/**
 * Simple in-memory audit logger. Stores every event in a local array.
 *
 * Useful in tests (assert what mutations fired) and during local development.
 * For production, implement `AuditLogger` and persist events to your database.
 *
 * @example
 * const audit = new InMemoryAuditLogger()
 * const policy = new PolicyEngine({ audit })
 * policy.addRole({ name: 'ADMIN', level: 10, permissions: ['*'] })
 * audit.getEvents() // [{ action: 'role.add', role: 'ADMIN', ... }]
 */
export class InMemoryAuditLogger implements AuditLogger {
  private events: AuditEvent[] = []

  log(event: AuditEvent): void {
    this.events.push({ ...event })
  }

  /** Returns a snapshot of all recorded events (oldest first). */
  getEvents(): AuditEvent[] {
    return [...this.events]
  }

  /** Returns only events matching the given action. */
  getEventsFor(action: AuditAction): AuditEvent[] {
    return this.events.filter((e) => e.action === action)
  }

  /** Clears all recorded events. */
  clear(): void {
    this.events = []
  }

  /** Filters events by one or more criteria (AND semantics). */
  query(q: AuditQuery): AuditEvent[] {
    const actions = q.action
      ? Array.isArray(q.action) ? q.action : [q.action]
      : null

    let results = this.events.filter((e) => {
      if (actions && !actions.includes(e.action)) return false
      if (q.userId !== undefined && e.userId !== q.userId) return false
      if (q.role !== undefined && e.role !== q.role) return false
      if (q.tenantId !== undefined && e.tenantId !== q.tenantId) return false
      if (q.since && e.timestamp < q.since) return false
      if (q.until && e.timestamp > q.until) return false
      return true
    })

    if (q.order === 'desc') results = results.slice().reverse()
    if (q.limit !== undefined) results = results.slice(0, q.limit)
    return results
  }

  /** Returns events since the given date. Shorthand for query({ since }). */
  since(date: Date): AuditEvent[] {
    return this.query({ since: date })
  }

  /** Returns events for a specific user. */
  forUser(userId: string): AuditEvent[] {
    return this.query({ userId })
  }

  /** Returns events for a specific role. */
  forRole(role: string): AuditEvent[] {
    return this.query({ role })
  }

  /** Returns events for a specific tenant. */
  forTenant(tenantId: string): AuditEvent[] {
    return this.query({ tenantId })
  }
}
