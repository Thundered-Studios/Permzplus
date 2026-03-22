import { describe, it, expect } from 'vitest'
import { BUILT_IN_ROLES, BUILT_IN_ROLE_NAMES } from '../src/roles'

describe('BUILT_IN_ROLES', () => {
  it('is an empty array', () => {
    expect(BUILT_IN_ROLES).toEqual([])
  })
})

describe('BUILT_IN_ROLE_NAMES', () => {
  it('is an empty array', () => {
    expect(BUILT_IN_ROLE_NAMES).toEqual([])
  })
})
