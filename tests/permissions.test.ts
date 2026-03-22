import { describe, it, expect } from 'vitest'
import { validatePermission, matchesPermission } from '../src/permissions'

describe('validatePermission', () => {
  it('returns true for wildcard "*"', () => {
    expect(validatePermission('*')).toBe(true)
  })

  it('returns true for valid resource:action strings', () => {
    expect(validatePermission('posts:read')).toBe(true)
    expect(validatePermission('users:ban')).toBe(true)
    expect(validatePermission('admin:panel')).toBe(true)
  })

  it('returns true for resource wildcard "posts:*"', () => {
    expect(validatePermission('posts:*')).toBe(true)
  })

  it('returns false for empty string', () => {
    expect(validatePermission('')).toBe(false)
  })

  it('returns false for plain word with no colon', () => {
    expect(validatePermission('invalid')).toBe(false)
  })

  it('returns false for too many colons', () => {
    expect(validatePermission('too:many:colons')).toBe(false)
  })

  it('returns false when resource is missing', () => {
    expect(validatePermission(':noResource')).toBe(false)
  })

  it('returns false when action is missing', () => {
    expect(validatePermission('noAction:')).toBe(false)
  })
})

describe('matchesPermission', () => {
  it('"*" pattern matches any permission', () => {
    expect(matchesPermission('posts:read', '*')).toBe(true)
    expect(matchesPermission('users:ban', '*')).toBe(true)
    expect(matchesPermission('anything:ever', '*')).toBe(true)
  })

  it('"posts:*" matches posts:read and posts:write but not users:read', () => {
    expect(matchesPermission('posts:read', 'posts:*')).toBe(true)
    expect(matchesPermission('posts:write', 'posts:*')).toBe(true)
    expect(matchesPermission('users:read', 'posts:*')).toBe(false)
  })

  it('"posts:read" matches only posts:read, not posts:write', () => {
    expect(matchesPermission('posts:read', 'posts:read')).toBe(true)
    expect(matchesPermission('posts:write', 'posts:read')).toBe(false)
  })
})
