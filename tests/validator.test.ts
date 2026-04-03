import { describe, it, expect } from 'vitest'
import { validate } from '../src/validator'
import type { RoleDefinition } from '../src/types'

const validRoles: RoleDefinition[] = [
  { name: 'VIEWER', level: 1, permissions: ['posts:read'] },
  { name: 'EDITOR', level: 2, permissions: ['posts:edit', 'posts:read'] },
  { name: 'ADMIN', level: 3, permissions: ['*'] },
]

describe('validate — clean policy', () => {
  it('returns valid:true with no issues for a well-formed policy', () => {
    const result = validate(validRoles)
    expect(result.valid).toBe(true)
    expect(result.issues).toHaveLength(0)
  })
})

describe('validate — invalid_level', () => {
  it('flags a negative level', () => {
    const roles: RoleDefinition[] = [{ name: 'BAD', level: -1, permissions: [] }]
    const { valid, issues } = validate(roles)
    expect(valid).toBe(false)
    expect(issues[0].type).toBe('invalid_level')
    expect(issues[0].role).toBe('BAD')
  })

  it('flags a non-integer level', () => {
    const roles: RoleDefinition[] = [{ name: 'BAD', level: 1.5, permissions: [] }]
    const { valid, issues } = validate(roles)
    expect(valid).toBe(false)
    expect(issues[0].type).toBe('invalid_level')
  })
})

describe('validate — duplicate_level', () => {
  it('flags two roles sharing the same level', () => {
    const roles: RoleDefinition[] = [
      { name: 'A', level: 1, permissions: [] },
      { name: 'B', level: 1, permissions: [] },
    ]
    const { valid, issues } = validate(roles)
    expect(valid).toBe(false)
    expect(issues.some(i => i.type === 'duplicate_level')).toBe(true)
  })
})

describe('validate — orphaned_group', () => {
  it('flags a group referenced by a role but not defined', () => {
    const roles: RoleDefinition[] = [
      { name: 'EDITOR', level: 1, permissions: [], groups: ['content-ops'] },
    ]
    const { valid, issues } = validate(roles, {})
    expect(valid).toBe(false)
    expect(issues[0].type).toBe('orphaned_group')
    expect(issues[0].detail).toContain('content-ops')
  })

  it('passes when all referenced groups are defined', () => {
    const roles: RoleDefinition[] = [
      { name: 'EDITOR', level: 1, permissions: [], groups: ['content-ops'] },
    ]
    const { valid } = validate(roles, { 'content-ops': ['posts:edit'] })
    expect(valid).toBe(true)
  })
})

describe('validate — invalid_permission', () => {
  it('flags a malformed permission string', () => {
    const roles: RoleDefinition[] = [
      { name: 'BAD', level: 1, permissions: ['not valid!'] },
    ]
    const { valid, issues } = validate(roles)
    expect(valid).toBe(false)
    expect(issues[0].type).toBe('invalid_permission')
  })
})
