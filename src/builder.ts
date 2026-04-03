/**
 * `createPermz` — a closure-based fluent builder that emits a `PolicySnapshot`
 * consumable directly by `PolicyEngine.fromJSON()` (the O(1) resolver).
 *
 * @example
 * ```ts
 * import { createPermz, PolicyEngine } from 'permzplus'
 *
 * const snapshot = createPermz({ name: 'EDITOR', level: 20 })
 *   .can('read',   'posts')
 *   .can('write',  'posts')
 *   .cannot('delete', 'posts')
 *   .build()
 *
 * const policy = PolicyEngine.fromJSON(snapshot)
 * policy.can('EDITOR', 'posts:read')  // true
 * ```
 *
 * Generic type parameters let callers lock down which actions and resources
 * are valid, giving full autocomplete and compile-time safety:
 *
 * ```ts
 * type Action   = 'read' | 'write' | 'delete'
 * type Resource = 'posts' | 'comments'
 *
 * createPermz<Action, Resource>({ name: 'MOD', level: 30 })
 *   .can('purge', 'posts')   // ✗ TS error — 'purge' not in Action
 * ```
 */

import type { PolicySnapshot } from './types'

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** Chainable builder returned by `createPermz()`. */
export interface PermzBuilder<A extends string, R extends string> {
  /**
   * Records an allow-rule for `action` on `resource`.
   * The `conditions` argument is captured in the type signature for
   * CASL-compatible DX; apply runtime conditions via `engine.defineRule()`
   * after calling `.build()`.
   */
  can(action: A, resource: R, conditions?: Record<string, unknown>): this
  /**
   * Records an explicit deny for `action` on `resource`.
   * Denies take priority over inherited allows (same semantics as `engine.denyFrom()`).
   */
  cannot(action: A, resource: R, conditions?: Record<string, unknown>): this
  /** Serialises all accumulated rules into the `PolicySnapshot` the resolver expects. */
  build(): PolicySnapshot
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Factory function returning a chainable, closure-based rule builder.
 *
 * @param config.name  - Role name written into the produced `PolicySnapshot`.
 * @param config.level - Hierarchy level (higher level inherits lower-level permissions).
 *
 * @typeParam A - Union of allowed action strings (defaults to `string`).
 * @typeParam R - Union of allowed resource strings (defaults to `string`).
 */
export function createPermz<A extends string = string, R extends string = string>(
  config: { name: string; level: number },
): PermzBuilder<A, R> {
  const p: string[] = []
  const d: string[] = []

  const b: PermzBuilder<A, R> = {
    can(action: A, resource: R, _conditions?: Record<string, unknown>) {
      p.push(`${resource}:${action}`)
      return b
    },
    cannot(action: A, resource: R, _conditions?: Record<string, unknown>) {
      d.push(`${resource}:${action}`)
      return b
    },
    build(): PolicySnapshot {
      return {
        roles: [{ name: config.name, level: config.level, permissions: [...p] }],
        denies: d.length ? { [config.name]: [...d] } : {},
        groups: {},
      }
    },
  }

  return b
}
