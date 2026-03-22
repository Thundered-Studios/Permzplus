import { describe, it, expect, vi, beforeEach } from 'vitest'
import { createGuard, expressGuard } from '../src/guard'
import { PolicyEngine } from '../src/policy'
import { UnknownRoleError } from '../src/errors'

describe('createGuard', () => {
  let policy: PolicyEngine
  let guard: (opts: { role: string; permission: string }) => boolean

  beforeEach(() => {
    policy = new PolicyEngine()
    guard = createGuard(policy)
  })

  it('returns true when USER has posts:read', () => {
    expect(guard({ role: 'USER', permission: 'posts:read' })).toBe(true)
  })

  it('returns false when USER does not have users:ban', () => {
    expect(guard({ role: 'USER', permission: 'users:ban' })).toBe(false)
  })

  it('throws UnknownRoleError for a non-existent role', () => {
    expect(() => guard({ role: 'NONEXISTENT', permission: 'posts:read' })).toThrow(UnknownRoleError)
  })
})

describe('expressGuard', () => {
  let policy: PolicyEngine
  let res: { status: ReturnType<typeof vi.fn>; json: ReturnType<typeof vi.fn> }
  let next: ReturnType<typeof vi.fn>

  beforeEach(() => {
    policy = new PolicyEngine()
    res = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
    }
    next = vi.fn()
  })

  it('calls next() with no arguments when role has the permission', () => {
    const req = { user: { role: 'USER' } }
    expressGuard(policy, 'posts:read')(req, res, next)
    expect(next).toHaveBeenCalledWith()
    expect(res.status).not.toHaveBeenCalled()
  })

  it('responds 403 and does NOT call next when role lacks the permission', () => {
    const req = { user: { role: 'USER' } }
    expressGuard(policy, 'users:ban')(req, res, next)
    expect(res.status).toHaveBeenCalledWith(403)
    expect(next).not.toHaveBeenCalled()
  })

  it('responds 401 when no role can be determined', () => {
    const req = {}
    expressGuard(policy, 'posts:read')(req, res, next)
    expect(res.status).toHaveBeenCalledWith(401)
    expect(next).not.toHaveBeenCalled()
  })
})
