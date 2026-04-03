/**
 * Query builder helpers for ABAC — converts permzplus rule conditions into
 * database WHERE clauses (Prisma, Mongoose, Drizzle, or any custom ORM).
 *
 * @example Prisma
 * ```ts
 * import { accessibleBy } from 'permzplus/query'
 *
 * const access = accessibleBy(policy, 'MEMBER', 'posts:read')
 * // access.unrestricted → true means no conditions, fetch all
 * // access.conditions   → array of plain objects to merge into WHERE
 *
 * const where = access.unrestricted
 *   ? {}
 *   : access.conditions.length === 0
 *     ? { id: null }  // no permission at all — return nothing
 *     : { OR: access.conditions }
 *
 * const posts = await prisma.post.findMany({ where })
 * ```
 *
 * @example Mongoose
 * ```ts
 * const access = accessibleBy(policy, 'MEMBER', 'posts:read')
 * const filter = access.unrestricted
 *   ? {}
 *   : { $or: access.conditions }
 * const posts = await Post.find(filter)
 * ```
 */

import type { SubjectConditionObject } from './conditions'
import { isObjectCondition } from './conditions'

// ---------------------------------------------------------------------------
// IPolicyEngine subset used here (avoids circular import from types.ts)
// ---------------------------------------------------------------------------

interface QueryablePolicyEngine {
  can(role: string, permission: string): boolean
  getConditionsFor(role: string, permission: string): Array<unknown>
}

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

export interface AccessibleByResult {
  /**
   * When `true` the role has this permission with **no conditions** — all
   * records are accessible and no WHERE clause filter is needed.
   */
  unrestricted: boolean

  /**
   * Serializable (object-form) conditions collected from all matching rules.
   * Each element is an independent condition — records matching ANY of them
   * are accessible (i.e. apply as `{ OR: conditions }` in Prisma or
   * `{ $or: conditions }` in Mongoose).
   *
   * Empty when `unrestricted` is `true` (no filter needed) or when the role
   * has no permission at all (no records accessible).
   */
  conditions: SubjectConditionObject[]

  /**
   * `true` if the role has the permission at all (with or without conditions).
   * When `false`, the user should be denied access entirely.
   */
  permitted: boolean
}

// ---------------------------------------------------------------------------
// accessibleBy
// ---------------------------------------------------------------------------

/**
 * Returns the set of conditions that determine which records a `role` can
 * perform `action` on for `resource`.
 *
 * Use the result to build a database query that only returns accessible records:
 * - `permitted: false` → deny access, return 0 records
 * - `unrestricted: true` → no filter, return all records
 * - `conditions.length > 0` → apply `OR` across conditions as a WHERE filter
 *
 * Only **object-form** conditions are included in `conditions` — function
 * conditions cannot be serialised to a query. If all conditions for a
 * permission are function-based, the result is `unrestricted: false` with an
 * empty `conditions` array; handle this case explicitly in your query layer.
 *
 * @param engine     The `PolicyEngine` instance.
 * @param role       The role to check (e.g. `'MEMBER'`).
 * @param permission The full permission string (e.g. `'posts:read'`).
 */
export function accessibleBy(
  engine: QueryablePolicyEngine,
  role: string,
  permission: string,
): AccessibleByResult {

  let permitted: boolean
  try {
    permitted = engine.can(role, permission)
  } catch {
    permitted = false
  }

  if (!permitted) {
    return { permitted: false, unrestricted: false, conditions: [] }
  }

  const allConditions = engine.getConditionsFor(role, permission)

  if (allConditions.length === 0) {
    // Permitted with no conditions → unrestricted access
    return { permitted: true, unrestricted: true, conditions: [] }
  }

  const objectConditions = (allConditions as SubjectConditionObject[]).filter(isObjectCondition)
  return {
    permitted: true,
    unrestricted: false,
    conditions: objectConditions,
  }
}

// ---------------------------------------------------------------------------
// Merge helper
// ---------------------------------------------------------------------------

/**
 * Merges multiple `AccessibleByResult` objects (e.g. when a user has multiple
 * roles). Returns a combined result where access is permitted if ANY role
 * permits it.
 *
 * @example
 * const r1 = accessibleBy(engine, 'MEMBER', 'posts:read')
 * const r2 = accessibleBy(engine, 'MODERATOR', 'posts:read')
 * const merged = mergeAccessible(r1, r2)
 */
export function mergeAccessible(...results: AccessibleByResult[]): AccessibleByResult {
  const anyPermitted = results.some((r) => r.permitted)
  if (!anyPermitted) return { permitted: false, unrestricted: false, conditions: [] }

  const anyUnrestricted = results.some((r) => r.unrestricted)
  if (anyUnrestricted) return { permitted: true, unrestricted: true, conditions: [] }

  const conditions = results.flatMap((r) => r.conditions)
  return { permitted: true, unrestricted: false, conditions }
}
