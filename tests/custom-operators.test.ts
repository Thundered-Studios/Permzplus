import { describe, it, expect } from 'vitest'
import { registerOperator, evalCondition } from '../src/conditions'

describe('registerOperator', () => {
  it('registers a custom operator and uses it in evalCondition', () => {
    registerOperator('$startsWith', (fieldValue, operand) =>
      typeof fieldValue === 'string' && fieldValue.startsWith(operand as string),
    )

    expect(evalCondition({ name: { $startsWith: 'foo' } }, { name: 'foobar' })).toBe(true)
    expect(evalCondition({ name: { $startsWith: 'foo' } }, { name: 'bazfoo' })).toBe(false)
  })

  it('throws when the operator name does not start with "$"', () => {
    expect(() => registerOperator('startsWith', () => true)).toThrow(
      'Operator name must start with "$", got: startsWith',
    )
  })

  it('passes ctx to the custom operator function', () => {
    registerOperator('$matchesCtx', (fieldValue, _operand, ctx) => fieldValue === ctx?.userId)

    const ctx = { userId: 'u1' }
    expect(evalCondition({ id: { $matchesCtx: null } }, { id: 'u1' }, ctx)).toBe(true)
    expect(evalCondition({ id: { $matchesCtx: null } }, { id: 'u2' }, ctx)).toBe(false)
  })
})

describe('$after', () => {
  it('returns true when fieldValue is after operand (ISO strings)', () => {
    expect(evalCondition({ ts: { $after: '2024-01-01' } }, { ts: '2025-06-15' })).toBe(true)
  })

  it('returns false when fieldValue is before operand', () => {
    expect(evalCondition({ ts: { $after: '2025-01-01' } }, { ts: '2024-06-15' })).toBe(false)
  })

  it('returns false when fieldValue equals operand (strict greater-than)', () => {
    expect(evalCondition({ ts: { $after: '2025-01-01' } }, { ts: '2025-01-01' })).toBe(false)
  })
})

describe('$before', () => {
  it('returns true when fieldValue is before operand (ISO strings)', () => {
    expect(evalCondition({ ts: { $before: '2025-01-01' } }, { ts: '2024-06-15' })).toBe(true)
  })

  it('returns false when fieldValue is after operand', () => {
    expect(evalCondition({ ts: { $before: '2024-01-01' } }, { ts: '2025-06-15' })).toBe(false)
  })

  it('returns false when fieldValue equals operand (strict less-than)', () => {
    expect(evalCondition({ ts: { $before: '2025-01-01' } }, { ts: '2025-01-01' })).toBe(false)
  })
})

describe('$between', () => {
  it('returns true when fieldValue is within the inclusive range (ISO strings)', () => {
    expect(
      evalCondition(
        { ts: { $between: ['2024-01-01', '2025-12-31'] } },
        { ts: '2024-06-15' },
      ),
    ).toBe(true)
  })

  it('returns true at the lower boundary (inclusive)', () => {
    expect(
      evalCondition(
        { ts: { $between: ['2024-01-01', '2025-12-31'] } },
        { ts: '2024-01-01' },
      ),
    ).toBe(true)
  })

  it('returns true at the upper boundary (inclusive)', () => {
    expect(
      evalCondition(
        { ts: { $between: ['2024-01-01', '2025-12-31'] } },
        { ts: '2025-12-31' },
      ),
    ).toBe(true)
  })

  it('returns false when fieldValue is outside the range', () => {
    expect(
      evalCondition(
        { ts: { $between: ['2024-01-01', '2024-12-31'] } },
        { ts: '2025-06-01' },
      ),
    ).toBe(false)
  })

  it('works with numeric timestamps', () => {
    const min = new Date('2024-01-01').getTime()
    const max = new Date('2025-12-31').getTime()
    const inside = new Date('2024-06-15').getTime()
    const outside = new Date('2026-01-01').getTime()

    expect(evalCondition({ ts: { $between: [min, max] } }, { ts: inside })).toBe(true)
    expect(evalCondition({ ts: { $between: [min, max] } }, { ts: outside })).toBe(false)
  })

  it('returns false when operand is not a two-element array', () => {
    expect(evalCondition({ ts: { $between: '2024-01-01' } }, { ts: '2024-06-15' })).toBe(false)
    expect(
      evalCondition({ ts: { $between: ['2024-01-01'] } }, { ts: '2024-06-15' }),
    ).toBe(false)
  })
})
