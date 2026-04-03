import { describe, it, expect } from 'vitest'
import { PolicyEngine } from '../src/policy'

function makeEngine() {
  return new PolicyEngine({
    roles: [
      { name: 'VIEWER', level: 1, permissions: ['post.title:read', 'post.body:read'] },
      { name: 'EDITOR', level: 2, permissions: ['post.title:read', 'post.body:read', 'post.status:read', 'post.title:edit', 'post.body:edit'] },
    ],
  })
}

describe('PolicyEngine.filterFields', () => {
  it('returns only allowed fields for the given action', () => {
    const engine = makeEngine()
    const obj = { title: 'Hello', body: 'World', secret: 'hidden', status: 'draft' }
    expect(engine.filterFields('VIEWER', obj, 'post', 'read')).toEqual({ title: 'Hello', body: 'World' })
  })

  it('includes all fields the role can access', () => {
    const engine = makeEngine()
    const obj = { title: 'T', body: 'B', status: 'published', secret: 'x' }
    expect(engine.filterFields('EDITOR', obj, 'post', 'read')).toEqual({ title: 'T', body: 'B', status: 'published' })
  })

  it('returns empty object when no field permissions exist', () => {
    const engine = makeEngine()
    expect(engine.filterFields('VIEWER', { title: 'T' }, 'post', 'edit')).toEqual({})
  })

  it('omits keys absent from obj even if permitted', () => {
    const engine = makeEngine()
    expect(engine.filterFields('VIEWER', { title: 'T' }, 'post', 'read')).toEqual({ title: 'T' })
  })
})

describe('PermissionContext.filterFields', () => {
  it('filters via bound roles', () => {
    const engine = makeEngine()
    const ctx = engine.createContext('VIEWER')
    const obj = { title: 'T', body: 'B', secret: 'x' }
    expect(ctx.filterFields(obj, 'post', 'read')).toEqual({ title: 'T', body: 'B' })
  })

  it('union of fields when multiple roles are bound', () => {
    const engine = makeEngine()
    const ctx = engine.createContext(['VIEWER', 'EDITOR'])
    const obj = { title: 'T', body: 'B', status: 'draft', secret: 'x' }
    expect(ctx.filterFields(obj, 'post', 'read')).toEqual({ title: 'T', body: 'B', status: 'draft' })
  })
})
