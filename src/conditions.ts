/**
 * Subject condition types and evaluation for ABAC (Attribute-Based Access Control).
 *
 * A `SubjectCondition` is attached to a permission rule via `PolicyEngine.defineRule()`.
 * When `can(role, permission, subject)` is called with a subject, all matching
 * conditions are evaluated against it.
 *
 * Two forms are supported:
 *
 * **Function condition** — evaluated at runtime, not serializable:
 * ```ts
 * policy.defineRule('MEMBER', 'posts:edit', (post, ctx) => post.authorId === ctx?.userId)
 * ```
 *
 * **Object condition** — MongoDB-style operators, evaluated at runtime AND serializable:
 * ```ts
 * policy.defineRule('MEMBER', 'posts:read', { status: 'published' })
 * policy.defineRule('MODERATOR', 'posts:edit', { status: { $in: ['draft', 'pending'] } })
 * ```
 *
 * Supported operators: `$eq`, `$ne`, `$gt`, `$gte`, `$lt`, `$lte`, `$in`, `$nin`,
 * `$exists`, `$and`, `$or`, `$nor`.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * A function condition. Receives the subject and an optional context object
 * (e.g. `{ userId: 'abc' }`) and returns a boolean.
 */
export type SubjectConditionFn<T = unknown> = (subject: T, ctx?: Record<string, unknown>) => boolean

/**
 * A plain-object condition using MongoDB-style operators.
 * Can be serialised to JSON and used to build database WHERE clauses.
 */
export type SubjectConditionObject = Record<string, unknown>

/** Either form of subject condition. */
export type SubjectCondition<T = unknown> = SubjectConditionFn<T> | SubjectConditionObject

/** Narrows a condition to the serializable object form. */
export function isObjectCondition(c: SubjectCondition): c is SubjectConditionObject {
  return typeof c === 'object' && c !== null
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

/**
 * Evaluates a `SubjectCondition` against a subject value.
 *
 * - **Function conditions**: called as `condition(subject, ctx)`.
 * - **Object conditions**: each field is matched using MongoDB-style semantics.
 *   The subject must be a plain object; non-object subjects always return `false`.
 *
 * @param condition The condition to evaluate.
 * @param subject   The value to test (e.g. a database record).
 * @param ctx       Optional context passed to function conditions (e.g. `{ userId }`).
 */
export function evalCondition(
  condition: SubjectCondition,
  subject: unknown,
  ctx?: Record<string, unknown>,
): boolean {
  if (typeof condition === 'function') {
    return condition(subject, ctx)
  }
  if (typeof subject !== 'object' || subject === null) return false
  return matchesCondition(subject as Record<string, unknown>, condition, ctx)
}

/**
 * Resolves a dot-path string (e.g. `"user.id"`) against `ctx`.
 * Returns `undefined` if any segment is missing.
 */
function resolvePath(path: string, ctx: Record<string, unknown>): unknown {
  let cur: unknown = ctx
  for (const part of path.split('.')) cur = (cur as Record<string, unknown>)?.[part]
  return cur
}

/**
 * Expands `{{dot.path}}` macros in `val` using values from `ctx`.
 * A string consisting of a single macro (e.g. `"{{user.id}}"`) is replaced
 * with the resolved value directly (preserving its original type).
 * Mixed strings (e.g. `"prefix-{{user.id}}"`) are coerced to strings.
 */
export function expandMacros(val: string, ctx: Record<string, unknown>): unknown {
  if (!val.includes('{{')) return val
  const single = val.match(/^\{\{([^}]+)\}\}$/)
  if (single) return resolvePath(single[1].trim(), ctx)
  return val.replace(/\{\{([^}]+)\}\}/g, (_, p) => String(resolvePath(p.trim(), ctx) ?? ''))
}

/**
 * Evaluates a MongoDB-style condition object against a plain subject record.
 *
 * @example
 * matchesCondition({ status: 'published', authorId: 'u1' }, { status: 'published' }) // true
 * matchesCondition({ count: 5 }, { count: { $gte: 3, $lte: 10 } })                  // true
 * matchesCondition({ tags: ['a','b'] }, { tags: { $in: ['a'] } })                   // true
 */
export function matchesCondition(
  subject: Record<string, unknown>,
  condition: SubjectConditionObject,
  ctx?: Record<string, unknown>,
): boolean {
  for (const [key, value] of Object.entries(condition)) {
    if (key === '$and') {
      if (!Array.isArray(value)) return false
      if (!(value as SubjectConditionObject[]).every((c) => matchesCondition(subject, c, ctx))) return false
    } else if (key === '$or') {
      if (!Array.isArray(value)) return false
      if (!(value as SubjectConditionObject[]).some((c) => matchesCondition(subject, c, ctx))) return false
    } else if (key === '$nor') {
      if (!Array.isArray(value)) return false
      if ((value as SubjectConditionObject[]).some((c) => matchesCondition(subject, c, ctx))) return false
    } else {
      const fieldValue = subject[key]
      if (!evalFieldValue(fieldValue, value, ctx)) return false
    }
  }
  return true
}

// ---------------------------------------------------------------------------
// Internal field evaluation
// ---------------------------------------------------------------------------

function evalFieldValue(fieldValue: unknown, rawCondition: unknown, ctx?: Record<string, unknown>): boolean {
  // Expand possession macros in string conditions (e.g. "{{user.id}}")
  const condition = ctx && typeof rawCondition === 'string' ? expandMacros(rawCondition, ctx) : rawCondition
  // Direct equality — handles strings, numbers, booleans, null
  if (condition === null || typeof condition !== 'object') {
    return fieldValue === condition
  }

  const ops = condition as Record<string, unknown>
  for (const [op, operand] of Object.entries(ops)) {
    switch (op) {
      case '$eq':
        if (fieldValue !== operand) return false
        break
      case '$ne':
        if (fieldValue === operand) return false
        break
      case '$gt':
        if ((fieldValue as number) <= (operand as number)) return false
        break
      case '$gte':
        if ((fieldValue as number) < (operand as number)) return false
        break
      case '$lt':
        if ((fieldValue as number) >= (operand as number)) return false
        break
      case '$lte':
        if ((fieldValue as number) > (operand as number)) return false
        break
      case '$in':
        if (!Array.isArray(operand)) return false
        if (Array.isArray(fieldValue)) {
          // any overlap
          if (!fieldValue.some((v) => operand.includes(v))) return false
        } else {
          if (!operand.includes(fieldValue)) return false
        }
        break
      case '$nin':
        if (!Array.isArray(operand)) return false
        if (Array.isArray(fieldValue)) {
          if (fieldValue.some((v) => operand.includes(v))) return false
        } else {
          if (operand.includes(fieldValue)) return false
        }
        break
      case '$exists':
        if (operand) {
          if (fieldValue === undefined || fieldValue === null) return false
        } else {
          if (fieldValue !== undefined && fieldValue !== null) return false
        }
        break
      case '$regex': {
        if (typeof fieldValue !== 'string') return false
        const re = operand instanceof RegExp ? operand : new RegExp(operand as string)
        if (!re.test(fieldValue)) return false
        break
      }
      default:
        // Unknown operator — treat as no-match to be safe
        return false
    }
  }
  return true
}
