import type { AuditAction, AuditEvent, AuditLogger } from './types'

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
}
