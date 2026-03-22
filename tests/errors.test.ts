import { describe, it, expect } from 'vitest'
import {
  PermissionDeniedError,
  UnknownRoleError,
  InvalidPermissionError,
  AdapterError,
} from '../src/errors'

describe('PermissionDeniedError', () => {
  it('is an instance of Error', () => {
    const err = new PermissionDeniedError('USER', 'users:ban')
    expect(err).toBeInstanceOf(Error)
  })

  it('has name "PermissionDeniedError"', () => {
    const err = new PermissionDeniedError('USER', 'users:ban')
    expect(err.name).toBe('PermissionDeniedError')
  })

  it('message includes the role and permission', () => {
    const err = new PermissionDeniedError('USER', 'users:ban')
    expect(err.message).toContain('USER')
    expect(err.message).toContain('users:ban')
  })
})

describe('UnknownRoleError', () => {
  it('is an instance of Error', () => {
    const err = new UnknownRoleError('PHANTOM')
    expect(err).toBeInstanceOf(Error)
  })

  it('has name "UnknownRoleError"', () => {
    const err = new UnknownRoleError('PHANTOM')
    expect(err.name).toBe('UnknownRoleError')
  })

  it('message includes the role name', () => {
    const err = new UnknownRoleError('PHANTOM')
    expect(err.message).toContain('PHANTOM')
  })
})

describe('InvalidPermissionError', () => {
  it('is an instance of Error', () => {
    const err = new InvalidPermissionError('bad permission!')
    expect(err).toBeInstanceOf(Error)
  })

  it('has name "InvalidPermissionError"', () => {
    const err = new InvalidPermissionError('bad permission!')
    expect(err.name).toBe('InvalidPermissionError')
  })
})

describe('AdapterError', () => {
  it('is an instance of Error', () => {
    const err = new AdapterError('something went wrong')
    expect(err).toBeInstanceOf(Error)
  })

  it('has name "AdapterError"', () => {
    const err = new AdapterError('something went wrong')
    expect(err.name).toBe('AdapterError')
  })
})
