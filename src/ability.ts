/**
 * Fluent ability builder for PermzPlus.
 *
 * `defineAbility` provides a CASL-inspired callback API for constructing a
 * `PolicyEngine` without manually calling `addRole` on each line.
 *
 * @example
 * ```ts
 * import { defineAbility } from 'permzplus'
 *
 * const policy = defineAbility(({ role }) => {
 *   role('SUPER_ADMIN', 3, (can) => {
 *     can('*')
 *   })
 *   role('ORG_ADMIN', 2, (can, cannot) => {
 *     can('sites:create', 'sites:edit', 'sites:delete')
 *     can('templates:*')
 *     cannot('billing:delete')
 *   })
 *   role('MEMBER', 1, (can) => {
 *     can('content:read', 'content:create')
 *     can('assignments:view-own')
 *   })
 * })
 *
 * policy.can('ORG_ADMIN', 'sites:create') // true
 * policy.can('MEMBER', 'content:read')    // true (also inherited by ORG_ADMIN)
 * policy.safeCan('', 'content:read')      // false — safe for unauthenticated users
 * ```
 */

import { PolicyEngine } from './policy'
import type { PolicyOptions } from './types'

// ---------------------------------------------------------------------------
// Internal role builder
// ---------------------------------------------------------------------------

class RoleBuilder {
  private _permissions: string[] = []
  private _denies: string[] = []

  can(...permissions: string[]): this {
    this._permissions.push(...permissions)
    return this
  }

  cannot(...permissions: string[]): this {
    this._denies.push(...permissions)
    return this
  }

  /** @internal */
  getPermissions(): string[] { return [...this._permissions] }
  /** @internal */
  getDenies(): string[] { return [...this._denies] }
}

interface RoleSpec {
  name: string
  level: number
  builder: RoleBuilder
}

// ---------------------------------------------------------------------------
// AbilityBuilder
// ---------------------------------------------------------------------------

/**
 * Fluent builder that accumulates role definitions and constructs a
 * `PolicyEngine` via `.build()`.
 *
 * @example
 * const builder = new AbilityBuilder()
 * builder.role('ADMIN', 2, (can) => can('*'))
 * builder.role('MEMBER', 1, (can) => can('content:read'))
 * const policy = builder.build()
 */
export class AbilityBuilder {
  private specs: RoleSpec[] = []
  private options: Omit<PolicyOptions, 'roles'>

  constructor(options?: Omit<PolicyOptions, 'roles'>) {
    this.options = options ?? {}
  }

  /**
   * Defines a role with its hierarchy level and permissions.
   *
   * @param name    - Role name, e.g. `'ADMIN'`
   * @param level   - Numeric hierarchy level (higher level inherits lower-level perms)
   * @param define  - Callback receiving `can(...perms)` and `cannot(...perms)` functions
   *
   * @example
   * builder.role('ORG_ADMIN', 2, (can, cannot) => {
   *   can('sites:create', 'sites:edit')
   *   cannot('billing:delete')
   * })
   */
  role(
    name: string,
    level: number,
    define: (can: (...perms: string[]) => void, cannot: (...perms: string[]) => void) => void,
  ): this {
    const builder = new RoleBuilder()
    define((...perms) => builder.can(...perms), (...perms) => builder.cannot(...perms))
    this.specs.push({ name, level, builder })
    return this
  }

  /**
   * Builds and returns a fully configured `PolicyEngine` from the accumulated
   * role definitions.
   */
  build(): PolicyEngine {
    const engine = new PolicyEngine(this.options)
    for (const { name, level, builder } of this.specs) {
      engine.addRole({ name, level, permissions: builder.getPermissions() })
      for (const perm of builder.getDenies()) {
        engine.denyFrom(name, perm)
      }
    }
    return engine
  }
}

// ---------------------------------------------------------------------------
// defineAbility
// ---------------------------------------------------------------------------

/**
 * Convenience function that creates a `PolicyEngine` using a CASL-inspired
 * callback API. Internally uses `AbilityBuilder`.
 *
 * The callback receives a `role()` function identical to
 * `AbilityBuilder.role()`.
 *
 * @param define  - Builder callback
 * @param options - Optional `PolicyEngine` options (hooks, debug mode)
 * @returns A fully configured `PolicyEngine`
 *
 * @example
 * const policy = defineAbility(({ role }) => {
 *   role('SUPER_ADMIN', 3, (can) => can('*'))
 *   role('ORG_ADMIN', 2, (can, cannot) => {
 *     can('sites:*', 'templates:*', 'org:manage')
 *     cannot('billing:delete')
 *   })
 *   role('MEMBER', 1, (can) => {
 *     can('content:read', 'content:create', 'submissions:create')
 *   })
 * })
 *
 * policy.can('ORG_ADMIN', 'sites:create') // true
 * policy.can('MEMBER', 'content:read')    // true (inherited by ORG_ADMIN)
 * policy.safeCan('', 'content:read')      // false — safe for unauthenticated users
 */
export function defineAbility(
  define: (builder: Pick<AbilityBuilder, 'role'>) => void,
  options?: Omit<PolicyOptions, 'roles'>,
): PolicyEngine {
  const builder = new AbilityBuilder(options)
  define(builder)
  return builder.build()
}
