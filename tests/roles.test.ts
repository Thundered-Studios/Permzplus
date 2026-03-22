import { describe, it, expect } from 'vitest'
import { BUILT_IN_ROLES, BUILT_IN_ROLE_NAMES } from '../src/roles'

describe('BUILT_IN_ROLES', () => {
  it('has exactly 6 roles', () => {
    expect(BUILT_IN_ROLES).toHaveLength(6)
  })

  it('SUPER_ADMIN has level 100', () => {
    const superAdmin = BUILT_IN_ROLES.find((r) => r.name === 'SUPER_ADMIN')
    expect(superAdmin?.level).toBe(100)
  })

  it('GUEST has level 0', () => {
    const guest = BUILT_IN_ROLES.find((r) => r.name === 'GUEST')
    expect(guest?.level).toBe(0)
  })

  it('SUPER_ADMIN permissions include "*"', () => {
    const superAdmin = BUILT_IN_ROLES.find((r) => r.name === 'SUPER_ADMIN')
    expect(superAdmin?.permissions).toContain('*')
  })

  it('roles are ordered ascending by level (GUEST lowest, SUPER_ADMIN highest)', () => {
    const levels = BUILT_IN_ROLES.map((r) => r.level)
    const sorted = [...levels].sort((a, b) => a - b)
    expect(levels).toEqual(sorted)
  })
})

describe('BUILT_IN_ROLE_NAMES', () => {
  it('includes "MODERATOR"', () => {
    expect(BUILT_IN_ROLE_NAMES).toContain('MODERATOR')
  })
})
