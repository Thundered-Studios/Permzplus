import { describe, it, expect, beforeEach } from 'vitest'
import { InMemoryAdapter } from '../src/adapter'
import { PolicyEngine } from '../src/policy'
import { AdapterError, UnknownRoleError } from '../src/errors'
import type { RoleDefinition } from '../src/types'

const ROLES: RoleDefinition[] = [
  { name: 'VIEWER', level: 10, permissions: ['posts:read'] },
  { name: 'EDITOR', level: 20, permissions: ['posts:write'] },
  { name: 'ADMIN', level: 30, permissions: ['users:manage'] },
]

// ---------------------------------------------------------------------------
// InMemoryAdapter — user-role assignment
// ---------------------------------------------------------------------------

describe('InMemoryAdapter — user-role assignment', () => {
  let adapter: InMemoryAdapter

  beforeEach(() => {
    adapter = new InMemoryAdapter()
  })

  it('getUserRoles returns empty array for unknown user', async () => {
    expect(await adapter.getUserRoles('user-1')).toEqual([])
  })

  it('assignRole then getUserRoles returns the role', async () => {
    await adapter.assignRole('user-1', 'EDITOR')
    expect(await adapter.getUserRoles('user-1')).toContain('EDITOR')
  })

  it('assigning the same role twice is a no-op', async () => {
    await adapter.assignRole('user-1', 'EDITOR')
    await adapter.assignRole('user-1', 'EDITOR')
    const roles = await adapter.getUserRoles('user-1')
    expect(roles.filter((r) => r === 'EDITOR')).toHaveLength(1)
  })

  it('revokeRole removes the role', async () => {
    await adapter.assignRole('user-1', 'EDITOR')
    await adapter.revokeRole('user-1', 'EDITOR')
    expect(await adapter.getUserRoles('user-1')).not.toContain('EDITOR')
  })

  it('revokeRole is a no-op when assignment does not exist', async () => {
    await expect(adapter.revokeRole('user-1', 'EDITOR')).resolves.not.toThrow()
  })

  it('a user can hold multiple roles', async () => {
    await adapter.assignRole('user-1', 'VIEWER')
    await adapter.assignRole('user-1', 'EDITOR')
    const roles = await adapter.getUserRoles('user-1')
    expect(roles).toContain('VIEWER')
    expect(roles).toContain('EDITOR')
  })

  it('tenantId scopes assignments independently', async () => {
    await adapter.assignRole('user-1', 'ADMIN', 'tenant-a')
    await adapter.assignRole('user-1', 'VIEWER', 'tenant-b')

    expect(await adapter.getUserRoles('user-1', 'tenant-a')).toContain('ADMIN')
    expect(await adapter.getUserRoles('user-1', 'tenant-a')).not.toContain('VIEWER')

    expect(await adapter.getUserRoles('user-1', 'tenant-b')).toContain('VIEWER')
    expect(await adapter.getUserRoles('user-1', 'tenant-b')).not.toContain('ADMIN')
  })

  it('assignments without tenantId are isolated from tenanted assignments', async () => {
    await adapter.assignRole('user-1', 'EDITOR')
    await adapter.assignRole('user-1', 'ADMIN', 'tenant-x')

    expect(await adapter.getUserRoles('user-1')).toContain('EDITOR')
    expect(await adapter.getUserRoles('user-1')).not.toContain('ADMIN')

    expect(await adapter.getUserRoles('user-1', 'tenant-x')).toContain('ADMIN')
    expect(await adapter.getUserRoles('user-1', 'tenant-x')).not.toContain('EDITOR')
  })
})

// ---------------------------------------------------------------------------
// PolicyEngine — user-role methods
// ---------------------------------------------------------------------------

describe('PolicyEngine — user-role methods via InMemoryAdapter', () => {
  let policy: PolicyEngine

  beforeEach(async () => {
    const adapter = new InMemoryAdapter()
    for (const role of ROLES) {
      await adapter.saveRole(role)
    }
    policy = await PolicyEngine.fromAdapter(adapter)
  })

  it('throws AdapterError when no adapter is configured', async () => {
    const bare = new PolicyEngine({ roles: ROLES })
    await expect(bare.canUser('user-1', 'posts:read')).rejects.toThrow(AdapterError)
  })

  it('canUser returns false for user with no roles', async () => {
    expect(await policy.canUser('user-1', 'posts:read')).toBe(false)
  })

  it('canUser returns true when user has a role with the permission', async () => {
    await policy.assignRole('user-1', 'VIEWER')
    expect(await policy.canUser('user-1', 'posts:read')).toBe(true)
  })

  it('canUser returns false when user lacks the permission', async () => {
    await policy.assignRole('user-1', 'VIEWER')
    expect(await policy.canUser('user-1', 'posts:write')).toBe(false)
  })

  it('canUser respects inherited permissions', async () => {
    // EDITOR (level 20) inherits posts:read from VIEWER (level 10)
    await policy.assignRole('user-1', 'EDITOR')
    expect(await policy.canUser('user-1', 'posts:read')).toBe(true)
  })

  it('canUser returns true when any of multiple roles has the permission', async () => {
    await policy.assignRole('user-1', 'VIEWER')
    await policy.assignRole('user-1', 'ADMIN')
    expect(await policy.canUser('user-1', 'users:manage')).toBe(true)
    expect(await policy.canUser('user-1', 'posts:read')).toBe(true)
  })

  it('getUserRoles returns all roles for the user', async () => {
    await policy.assignRole('user-1', 'VIEWER')
    await policy.assignRole('user-1', 'EDITOR')
    const roles = await policy.getUserRoles('user-1')
    expect(roles).toContain('VIEWER')
    expect(roles).toContain('EDITOR')
  })

  it('assignRole throws UnknownRoleError for a role not in the engine', async () => {
    await expect(policy.assignRole('user-1', 'NONEXISTENT')).rejects.toThrow(UnknownRoleError)
  })

  it('revokeRole removes the role from the user', async () => {
    await policy.assignRole('user-1', 'EDITOR')
    await policy.revokeRole('user-1', 'EDITOR')
    expect(await policy.canUser('user-1', 'posts:write')).toBe(false)
  })

  it('createUserContext returns a context with the user roles', async () => {
    await policy.assignRole('user-1', 'EDITOR')
    const ctx = await policy.createUserContext('user-1')
    expect(ctx.can('posts:write')).toBe(true)
    expect(ctx.can('posts:read')).toBe(true)   // inherited
    expect(ctx.can('users:manage')).toBe(false)
    expect(ctx.userId).toBe('user-1')
  })

  it('createUserContext silently filters stale roles that no longer exist in engine', async () => {
    // Directly write a stale role into the adapter
    const adapter = new InMemoryAdapter()
    await adapter.assignRole('user-1', 'GHOST_ROLE')
    for (const role of ROLES) await adapter.saveRole(role)
    const p = await PolicyEngine.fromAdapter(adapter)
    const ctx = await p.createUserContext('user-1')
    // Should not throw; GHOST_ROLE is filtered
    expect(ctx.can('posts:read')).toBe(false)
  })

  it('tenantId scopes canUser correctly', async () => {
    await policy.assignRole('user-1', 'ADMIN', 'tenant-a')
    expect(await policy.canUser('user-1', 'users:manage', 'tenant-a')).toBe(true)
    expect(await policy.canUser('user-1', 'users:manage', 'tenant-b')).toBe(false)
    expect(await policy.canUser('user-1', 'users:manage')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// PolicyEngine — permission cache
// ---------------------------------------------------------------------------

describe('PolicyEngine — permission cache', () => {
  it('can() returns consistent results on repeated calls (cache hit)', () => {
    const policy = new PolicyEngine({ roles: ROLES })
    // First call populates cache; second should return same result
    expect(policy.can('EDITOR', 'posts:read')).toBe(true)
    expect(policy.can('EDITOR', 'posts:read')).toBe(true)
  })

  it('cache is invalidated after grantTo', () => {
    const policy = new PolicyEngine({ roles: ROLES })
    expect(policy.can('VIEWER', 'comments:read')).toBe(false)
    policy.grantTo('VIEWER', 'comments:read')
    expect(policy.can('VIEWER', 'comments:read')).toBe(true)
  })

  it('cache is invalidated after denyFrom', () => {
    const policy = new PolicyEngine({ roles: ROLES })
    expect(policy.can('EDITOR', 'posts:read')).toBe(true)
    policy.denyFrom('EDITOR', 'posts:read')
    expect(policy.can('EDITOR', 'posts:read')).toBe(false)
  })

  it('cache is invalidated after addRole introduces a new lower-level role', () => {
    const policy = new PolicyEngine({ roles: ROLES })
    // EDITOR (level 20) should not yet have comments:read
    expect(policy.can('EDITOR', 'comments:read')).toBe(false)
    // Add a role at level 15 — EDITOR should now inherit its permissions
    policy.addRole({ name: 'COMMENTER', level: 15, permissions: ['comments:read'] })
    expect(policy.can('EDITOR', 'comments:read')).toBe(true)
  })

  it('cache is invalidated after removeRole', () => {
    const policy = new PolicyEngine({ roles: ROLES })
    // EDITOR inherits posts:read from VIEWER
    expect(policy.can('EDITOR', 'posts:read')).toBe(true)
    policy.removeRole('VIEWER')
    expect(policy.can('EDITOR', 'posts:read')).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// PolicyEngine — debug mode
// ---------------------------------------------------------------------------

describe('PolicyEngine — debug mode', () => {
  it('does not throw when debug: true', () => {
    const policy = new PolicyEngine({ roles: ROLES, debug: true })
    expect(() => policy.can('VIEWER', 'posts:read')).not.toThrow()
  })

  it('debug mode does not change the return value of can()', () => {
    const normal = new PolicyEngine({ roles: ROLES })
    const debugged = new PolicyEngine({ roles: ROLES, debug: true })
    expect(debugged.can('VIEWER', 'posts:read')).toBe(normal.can('VIEWER', 'posts:read'))
    expect(debugged.can('VIEWER', 'users:manage')).toBe(normal.can('VIEWER', 'users:manage'))
  })
})

// ---------------------------------------------------------------------------
// PolicyEngine — onAdapterError hook
// ---------------------------------------------------------------------------

describe('PolicyEngine — onAdapterError hook', () => {
  it('calls onAdapterError when a fire-and-forget adapter write rejects', async () => {
    const errors: Array<{ err: Error; method: string }> = []

    const badAdapter = new InMemoryAdapter()
    // Monkey-patch saveRole to reject
    badAdapter.saveRole = async () => {
      throw new Error('DB unavailable')
    }

    for (const role of ROLES) {
      await (new InMemoryAdapter()).saveRole(role) // baseline save; use separate adapter
    }

    // Re-build engine with the patched adapter
    const patchedAdapter = new InMemoryAdapter()
    const p = await PolicyEngine.fromAdapter(patchedAdapter)
    // Re-attach hooks; rebind adapter manually via fromAdapter with patched saveRole
    const engineWithHook = await PolicyEngine.fromAdapter(
      Object.assign(new InMemoryAdapter(), {
        saveRole: async () => { throw new Error('DB unavailable') },
      }),
    )

    // Re-wire hooks via a fresh engine constructed with hooks
    const hookedPolicy = new PolicyEngine({
      roles: ROLES,
      hooks: {
        onAdapterError(err, method) {
          errors.push({ err, method })
        },
      },
    })
    // Manually attach an adapter that fails on saveRole
    // (accessing private field via any for testing purposes)
    ;(hookedPolicy as any).adapter = {
      saveRole: async () => { throw new Error('DB unavailable') },
      grantPermission: async () => {},
    }

    hookedPolicy.addRole({ name: 'TEST_ROLE', level: 5, permissions: ['x:y'] })

    // Give the microtask queue a tick to settle
    await new Promise((r) => setTimeout(r, 0))

    expect(errors.length).toBeGreaterThan(0)
    expect(errors[0].method).toBe('saveRole')
    expect(errors[0].err.message).toBe('DB unavailable')
  })
})
