import { describe, it, expect } from 'vitest'
import { InMemoryAdapter } from '../src/adapter'

describe('expiring role assignments', () => {
  it('role without expiry is still present after time passes', async () => {
    const adapter = new InMemoryAdapter()
    await adapter.assignRole('user1', 'admin')
    const roles = await adapter.getUserRoles('user1')
    expect(roles).toContain('admin')
  })

  it('role with expiresAt in the past is filtered out by getUserRoles', async () => {
    const adapter = new InMemoryAdapter()
    const pastDate = new Date(Date.now() - 1000) // 1 second ago
    await adapter.assignRole('user2', 'admin', undefined, { expiresAt: pastDate })
    const roles = await adapter.getUserRoles('user2')
    expect(roles).not.toContain('admin')
    expect(roles).toHaveLength(0)
  })

  it('role with expiresAt in the future is still returned', async () => {
    const adapter = new InMemoryAdapter()
    const futureDate = new Date(Date.now() + 60_000) // 1 minute from now
    await adapter.assignRole('user3', 'editor', undefined, { expiresAt: futureDate })
    const roles = await adapter.getUserRoles('user3')
    expect(roles).toContain('editor')
  })

  it('cleanExpiredAssignments removes only expired entries', async () => {
    const adapter = new InMemoryAdapter()
    const pastDate = new Date(Date.now() - 1000)
    const futureDate = new Date(Date.now() + 60_000)

    await adapter.assignRole('user4', 'admin', undefined, { expiresAt: pastDate })
    await adapter.assignRole('user4', 'editor', undefined, { expiresAt: futureDate })
    await adapter.assignRole('user4', 'viewer') // no expiry

    adapter.cleanExpiredAssignments()

    const roles = await adapter.getUserRoles('user4')
    expect(roles).not.toContain('admin')
    expect(roles).toContain('editor')
    expect(roles).toContain('viewer')
  })

  it('revokeRole still works normally with expiring assignments', async () => {
    const adapter = new InMemoryAdapter()
    const futureDate = new Date(Date.now() + 60_000)
    await adapter.assignRole('user5', 'admin', undefined, { expiresAt: futureDate })
    await adapter.assignRole('user5', 'editor')

    await adapter.revokeRole('user5', 'admin')
    const roles = await adapter.getUserRoles('user5')
    expect(roles).not.toContain('admin')
    expect(roles).toContain('editor')
  })

  it('tenant-scoped expiring assignments are isolated per tenant', async () => {
    const adapter = new InMemoryAdapter()
    const pastDate = new Date(Date.now() - 1000)
    const futureDate = new Date(Date.now() + 60_000)

    await adapter.assignRole('user6', 'admin', 'tenant-a', { expiresAt: pastDate })
    await adapter.assignRole('user6', 'admin', 'tenant-b', { expiresAt: futureDate })

    const rolesA = await adapter.getUserRoles('user6', 'tenant-a')
    const rolesB = await adapter.getUserRoles('user6', 'tenant-b')

    expect(rolesA).not.toContain('admin')
    expect(rolesB).toContain('admin')
  })
})
