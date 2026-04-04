import type {
  PolicyOptions,
  ContextOptions,
  DelegateOptions,
  RoleDefinition,
  PermzAdapter,
  IPolicyEngine,
  PolicyHooks,
  PolicySnapshot,
  PermissionCheckResult,
  AuditEvent,
  AuditLogger,
} from './types'
import { PermissionDeniedError, UnknownRoleError, InvalidPermissionError, AdapterError } from './errors'
import { validatePermission, matchesPermission } from './permissions'
import { PermissionContext } from './context'
import type { SubjectCondition } from './conditions'
import { evalCondition } from './conditions'
import { toBitmask as _toBitmask } from './bitmask'

// ---------------------------------------------------------------------------
// Bitwise action flags — zero-allocation fast path for the four most common
// permission actions. Stored as bitmasks alongside the Set-based permCache.
// ---------------------------------------------------------------------------

const A_READ   = 1 << 0   //  1
const A_WRITE  = 1 << 1   //  2
const A_DELETE = 1 << 2   //  4
const A_CREATE = 1 << 3   //  8
const A_ALL    = A_READ | A_WRITE | A_DELETE | A_CREATE  // 15

/** Maps common action strings to their bit. Unknown actions are undefined. */
const ACTION_BITS: Record<string, number | undefined> = {
  read:   A_READ,
  write:  A_WRITE,
  delete: A_DELETE,
  create: A_CREATE,
}

interface PermBits {
  /** Bits from a bare `*` permission — applies to every resource. */
  global: number
  /** Per-resource bits from `resource:action` and `resource:*` patterns. */
  res: Map<string, number>
}

// ---------------------------------------------------------------------------
// Scoped delegation context
// ---------------------------------------------------------------------------

class ScopedPermissionContext extends PermissionContext {
  private readonly _scope: Set<string>
  constructor(roles: string[], engine: IPolicyEngine, scope: string[], opts?: Omit<ContextOptions, 'role' | 'roles'>) {
    super(roles, engine, opts)
    this._scope = new Set(scope)
  }
  can(permission: string, subjectOrCondition?: unknown, condition?: () => boolean): boolean {
    if (!this._scope.has(permission)) return false
    return super.can(permission, subjectOrCondition as unknown, condition)
  }
}

function parseCSVLine(line: string): string[] {
  const result: string[] = []
  let cur = ''
  let inQuotes = false
  for (const ch of line) {
    if (ch === '"') { inQuotes = !inQuotes }
    else if (ch === ',' && !inQuotes) { result.push(cur); cur = '' }
    else cur += ch
  }
  result.push(cur)
  return result
}

export class PolicyEngine implements IPolicyEngine {
  private roles: Map<string, RoleDefinition>
  private denies: Map<string, Set<string>>
  private groups: Map<string, string[]>
  private adapter?: PermzAdapter
  private hooks: PolicyHooks
  private readonly debugMode: boolean
  private readonly auditLogger?: AuditLogger
  /** Cached resolved permission sets, keyed by role name. Cleared on any mutation. */
  private permCache: Map<string, Set<string>>
  /**
   * Two-level hot-path cache for subject-free, context-free `can()` calls.
   * Outer key: role name. Inner key: permission string.
   * Two Map.get() calls with zero string allocation — no key concatenation.
   * Cleared on any mutation. Targeted delete by role in denyFrom/removeDeny.
   */
  private checkCache: Map<string, Map<string, boolean>>
  /**
   * Bitwise permission bitmasks per role, built alongside permCache.
   * Enables O(1) checks for the four common actions without iterating the Set.
   */
  private permBitsCache: Map<string, PermBits>
  /**
   * Per-rule subject conditions. Key: `"role\x00permission"`, value: array of
   * conditions registered via `defineRule()`.
   */
  private ruleConditions: Map<string, SubjectCondition[]>

  constructor(options?: PolicyOptions) {
    this.roles = new Map()
    this.denies = new Map()
    this.groups = new Map()
    this.hooks = options?.hooks ?? {}
    this.debugMode = options?.debug ?? false
    this.auditLogger = options?.audit
    this.permCache = new Map()
    this.checkCache = new Map()
    this.permBitsCache = new Map()
    this.ruleConditions = new Map()

    if (options?.roles) {
      for (const role of options.roles) {
        this.roles.set(role.name, { ...role, permissions: [...role.permissions] })
      }
    }

    if (options?.permissions) {
      for (const [roleName, perms] of Object.entries(options.permissions)) {
        const def = this.roles.get(roleName)
        if (!def) {
          throw new UnknownRoleError(roleName)
        }
        const existing = new Set(def.permissions)
        for (const perm of perms) {
          if (!validatePermission(perm)) {
            throw new InvalidPermissionError(perm)
          }
          if (!existing.has(perm)) {
            def.permissions.push(perm)
            existing.add(perm)
          }
        }
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Internal helpers
  // ---------------------------------------------------------------------------

  /**
   * Fires an adapter promise and routes any error to the `onAdapterError` hook
   * instead of letting it propagate. The in-memory state is always updated
   * synchronously before this is called, so a persistence failure does not
   * corrupt the engine — but callers should wire up `onAdapterError` to alert
   * or retry so the DB does not silently drift.
   */
  private fireAndForget(promise: Promise<void> | undefined, method: string): void {
    promise?.catch((err: unknown) => {
      this.hooks.onAdapterError?.(err instanceof Error ? err : new Error(String(err)), method)
    })
  }

  /** Fires an audit event. Errors from async loggers are swallowed to avoid disrupting callers. */
  private fireAudit(event: Omit<AuditEvent, 'timestamp'>): void {
    if (!this.auditLogger) return
    const full: AuditEvent = { ...event, timestamp: new Date() }
    const result = this.auditLogger.log(full)
    if (result instanceof Promise) {
      result.catch(() => { /* audit errors must not disrupt permission checks */ })
    }
  }

  /** Clears the entire permission cache. Called on every mutation. */
  private invalidateCache(): void {
    this.permCache.clear()
    this.checkCache.clear()
    this.permBitsCache.clear()
  }

  /**
   * Builds a stable, flat cache key from a context object without JSON.stringify.
   * Keys are sorted for determinism; values are coerced to strings.
   */
  private stableContextKey(ctx: Record<string, unknown>): string {
    const keys = Object.keys(ctx)
    if (keys.length === 0) return ''
    keys.sort()
    let key = ''
    for (let i = 0; i < keys.length; i++) {
      key += keys[i] + '=' + String(ctx[keys[i]]) + '\x01'
    }
    return key
  }

  /**
   * Factory for PermissionCheckResult — ensures every returned object is
   * allocated with the same property order so V8 assigns a single hidden class.
   */
  private static makeResult(result: boolean, reason: string): PermissionCheckResult {
    return { result, reason }
  }

  /**
   * Computes the full set of permissions for a role by collecting permissions
   * from all roles whose level is less than or equal to this role's level
   * (hierarchical inheritance), expanding any referenced permission groups,
   * then subtracting any explicit denies for the role.
   *
   * Results are memoised in `permCache` and cleared on every mutation.
   */
  private resolveEffectivePermissions(role: string): Set<string> {
    const cached = this.permCache.get(role)
    if (cached) return cached

    const def = this.roles.get(role)
    if (!def) {
      throw new UnknownRoleError(role)
    }

    const level = def.level
    const effective = new Set<string>()

    for (const [, roleDef] of this.roles) {
      if (roleDef.level <= level) {
        for (const perm of roleDef.permissions) {
          effective.add(perm)
        }
        if (roleDef.groups) {
          for (const groupName of roleDef.groups) {
            for (const perm of this.resolveGroup(groupName)) {
              effective.add(perm)
            }
          }
        }
      }
    }

    const denied = this.denies.get(role)
    if (denied) {
      // Collect patterns to remove first to avoid mutating the Set mid-iteration.
      const toRemove: string[] = []
      for (const deniedPerm of denied) {
        for (const pattern of effective) {
          if (matchesPermission(deniedPerm, pattern) || pattern === deniedPerm) {
            toRemove.push(pattern)
          }
        }
      }
      for (let i = 0; i < toRemove.length; i++) {
        effective.delete(toRemove[i])
      }
    }

    this.permCache.set(role, effective)

    // Build bitwise layer for the four common actions — O(n) once per role per
    // cache generation; after this, common-action checks are O(1) via bits.
    const bits: PermBits = { global: 0, res: new Map() }
    for (const perm of effective) {
      if (perm === '*') {
        bits.global |= A_ALL
      } else {
        const ci = perm.indexOf(':')
        if (ci === -1) continue
        const resource = perm.slice(0, ci)
        const action   = perm.slice(ci + 1)
        if (action === '*') {
          bits.res.set(resource, (bits.res.get(resource) ?? 0) | A_ALL)
        } else {
          const bit = ACTION_BITS[action]
          if (bit !== undefined) {
            bits.res.set(resource, (bits.res.get(resource) ?? 0) | bit)
          }
        }
      }
    }
    this.permBitsCache.set(role, bits)

    return effective
  }

  /**
   * Returns the adapter, asserting it has user-role support (assignRole /
   * revokeRole / getUserRoles). Throws a descriptive AdapterError if either
   * condition is not met.
   */
  private requireUserAdapter(): PermzAdapter & Required<Pick<PermzAdapter, 'assignRole' | 'revokeRole' | 'getUserRoles'>> {
    if (!this.adapter) {
      throw new AdapterError(
        'No adapter configured. Call PolicyEngine.fromAdapter(adapter) to enable user-role methods.',
      )
    }
    if (
      typeof this.adapter.assignRole !== 'function' ||
      typeof this.adapter.revokeRole !== 'function' ||
      typeof this.adapter.getUserRoles !== 'function'
    ) {
      throw new AdapterError(
        'The current adapter does not support user-role assignment. ' +
          'Implement assignRole(), revokeRole(), and getUserRoles() on your adapter.',
      )
    }
    return this.adapter as PermzAdapter & Required<Pick<PermzAdapter, 'assignRole' | 'revokeRole' | 'getUserRoles'>>
  }

  // ---------------------------------------------------------------------------
  // ABAC — rule conditions
  // ---------------------------------------------------------------------------

  /**
   * Attaches a subject condition to a role+permission pair. When `can()` is
   * called with a subject, ALL registered conditions for the matching rule must
   * pass for the check to succeed.
   *
   * Multiple calls for the same role+permission accumulate conditions (AND semantics).
   * Use object-form conditions when you also need `accessibleBy()` query building.
   *
   * @example Function condition (runtime only)
   * ```ts
   * policy.defineRule('MEMBER', 'posts:edit',
   *   (post, ctx) => post.authorId === ctx?.userId)
   * ```
   *
   * @example Object condition (serializable + query-buildable)
   * ```ts
   * policy.defineRule('MEMBER', 'posts:read', { status: 'published' })
   * policy.defineRule('MODERATOR', 'posts:edit', { status: { $in: ['draft', 'pending'] } })
   * ```
   *
   * @throws {UnknownRoleError} If the role is not registered.
   * @throws {InvalidPermissionError} If the permission string is malformed.
   * @returns `this` for chaining.
   */
  defineRule(role: string, permission: string, condition: SubjectCondition): this {
    if (!this.roles.has(role)) throw new UnknownRoleError(role)
    if (!validatePermission(permission)) throw new InvalidPermissionError(permission)
    const key = `${role}\x00${permission}`
    if (!this.ruleConditions.has(key)) this.ruleConditions.set(key, [])
    this.ruleConditions.get(key)!.push(condition)
    return this
  }

  /**
   * Returns all conditions registered for a role+permission pair via `defineRule()`.
   * Used internally by `accessibleBy()`.
   */
  getConditionsFor(role: string, permission: string): SubjectCondition[] {
    const key = `${role}\x00${permission}`
    return this.ruleConditions.get(key) ?? []
  }

  // ---------------------------------------------------------------------------
  // Permission group API
  // ---------------------------------------------------------------------------

  /**
   * Registers a named permission group — a reusable set of permissions that
   * can be referenced from any role definition via the `groups` array.
   *
   * @throws {InvalidPermissionError} If any permission string is malformed.
   * @returns `this` for chaining.
   */
  defineGroup(name: string, permissions: string[]): this {
    for (const perm of permissions) {
      if (!perm.startsWith('@') && !validatePermission(perm)) {
        throw new InvalidPermissionError(perm)
      }
    }
    this.groups.set(name, [...permissions])
    this.invalidateCache()
    return this
  }

  private resolveGroup(name: string, visiting = new Set<string>()): string[] {
    if (visiting.has(name)) {
      throw new Error(`Circular group reference detected: ${[...visiting, name].join(' → ')}`)
    }
    const members = this.groups.get(name)
    if (!members) return []
    visiting.add(name)
    const result: string[] = []
    for (const m of members) {
      if (m.startsWith('@')) {
        result.push(...this.resolveGroup(m.slice(1), new Set(visiting)))
      } else {
        result.push(m)
      }
    }
    return result
  }

  // ---------------------------------------------------------------------------
  // Core permission checks
  // ---------------------------------------------------------------------------

  /**
   * Returns `true` if the given role has the specified permission, either directly
   * or through role-level inheritance. Wildcard patterns (e.g. `*`, `posts:*`) are
   * supported on the stored permission side.
   *
   * When a `subject` is provided, any conditions registered via `defineRule()` for
   * the matching rule are evaluated against it. All conditions must pass (AND logic).
   * Pass `ctx` to supply runtime values (e.g. `{ userId }`) to function conditions.
   *
   * @example Subject-aware check
   * ```ts
   * policy.defineRule('MEMBER', 'posts:edit', (post, ctx) => post.authorId === ctx?.userId)
   * policy.can('MEMBER', 'posts:edit', post, { userId: 'u1' })  // true only if post.authorId === 'u1'
   * ```
   *
   * @throws {UnknownRoleError} If the role is not registered.
   * @throws {InvalidPermissionError} If the permission string is malformed.
   */
  can(role: string, permission: string, subject?: unknown, ctx?: Record<string, unknown>): boolean {
    // -----------------------------------------------------------------------
    // Level 1 — two-level Map lookup. ZERO string allocation, ZERO regex.
    // This is the only code that runs on the overwhelming majority of calls.
    // We intentionally check cache before validation: entries only exist if
    // they were written by a prior validated call, so correctness is intact.
    // -----------------------------------------------------------------------
    if (subject === undefined && ctx === undefined && !this.debugMode) {
      const roleCache = this.checkCache.get(role)
      if (roleCache !== undefined) {
        const cached = roleCache.get(permission)
        if (cached !== undefined) return cached
      }
    }

    // -----------------------------------------------------------------------
    // Slow path (cache miss / debug / subject / ctx) — validate once.
    // -----------------------------------------------------------------------
    if (!this.roles.has(role)) throw new UnknownRoleError(role)
    if (!validatePermission(permission)) throw new InvalidPermissionError(permission)

    // -----------------------------------------------------------------------
    // Level 2 — resolve effective permissions (populates permCache +
    // permBitsCache; O(n) only on the first call per role per generation).
    // -----------------------------------------------------------------------
    const effective = this.resolveEffectivePermissions(role)

    // -----------------------------------------------------------------------
    // Level 3 — bitwise fast path for read / write / delete / create.
    // Definitive O(1) answer for common actions; no Set iteration needed.
    // Only used when there is no ABAC subject (matchedPattern not required).
    // -----------------------------------------------------------------------
    if (subject === undefined && !this.debugMode) {
      const ci = permission.indexOf(':')
      if (ci !== -1) {
        const bit = ACTION_BITS[permission.slice(ci + 1)]
        if (bit !== undefined) {
          const bits = this.permBitsCache.get(role)
          if (bits !== undefined) {
            const resource = permission.slice(0, ci)
            const allowed  = (bits.global & bit) !== 0 || ((bits.res.get(resource) ?? 0) & bit) !== 0
            // Write to two-level cache (ctx calls skip this branch)
            if (ctx === undefined) {
              let roleCache = this.checkCache.get(role)
              if (roleCache === undefined) { roleCache = new Map(); this.checkCache.set(role, roleCache) }
              roleCache.set(permission, allowed)
            }
            return allowed
          }
        }
      }
    }

    // -----------------------------------------------------------------------
    // Level 4 — Set iteration (custom actions; matchedPattern for ABAC).
    // -----------------------------------------------------------------------
    let matched = false
    let matchedPattern: string | undefined
    for (const pattern of effective) {
      if (matchesPermission(permission, pattern)) {
        matched = true
        matchedPattern = pattern
        break
      }
    }

    if (!matched) {
      if (this.debugMode) {
        // eslint-disable-next-line no-console
        console.debug(`[permzplus] can("${role}", "${permission}") → false | No permission matching "${permission}" found for role "${role}"`)
      }
      if (subject === undefined && ctx === undefined && !this.debugMode) {
        let roleCache = this.checkCache.get(role)
        if (roleCache === undefined) { roleCache = new Map(); this.checkCache.set(role, roleCache) }
        roleCache.set(permission, false)
      }
      return false
    }

    // -----------------------------------------------------------------------
    // Level 5 — ABAC subject conditions (AND semantics; all must pass).
    // -----------------------------------------------------------------------
    if (subject !== undefined) {
      const conditions = this.getConditionsFor(role, matchedPattern ?? permission)
      if (conditions.length > 0) {
        let conditionsMet = true
        for (let i = 0; i < conditions.length; i++) {
          if (!evalCondition(conditions[i], subject, ctx)) {
            conditionsMet = false
            break
          }
        }
        if (this.debugMode) {
          // eslint-disable-next-line no-console
          console.debug(`[permzplus] can("${role}", "${permission}") → ${conditionsMet} | Conditions ${conditionsMet ? 'passed' : 'failed'} for subject`)
        }
        return conditionsMet
      }
    }

    if (this.debugMode) {
      const { reason } = this.canWithReason(role, permission)
      // eslint-disable-next-line no-console
      console.debug(`[permzplus] can("${role}", "${permission}") → true | ${reason}`)
    }

    if (subject === undefined && ctx === undefined && !this.debugMode) {
      let roleCache = this.checkCache.get(role)
      if (roleCache === undefined) { roleCache = new Map(); this.checkCache.set(role, roleCache) }
      roleCache.set(permission, true)
    }
    return true
  }

  /**
   * Returns `true` if the given role does NOT have the specified permission.
   * Accepts an optional subject and context for ABAC condition evaluation.
   *
   * @throws {UnknownRoleError} If the role is not registered.
   * @throws {InvalidPermissionError} If the permission string is malformed.
   */
  cannot(role: string, permission: string, subject?: unknown, ctx?: Record<string, unknown>): boolean {
    return !this.can(role, permission, subject, ctx)
  }

  /**
   * Asserts that the given role has the specified permission.
   * Accepts an optional subject and context for ABAC condition evaluation.
   *
   * @throws {PermissionDeniedError} If the role lacks the permission.
   * @throws {UnknownRoleError} If the role is not registered.
   * @throws {InvalidPermissionError} If the permission string is malformed.
   */
  assert(role: string, permission: string, subject?: unknown, ctx?: Record<string, unknown>): void {
    if (!this.can(role, permission, subject, ctx)) {
      throw new PermissionDeniedError(role, permission)
    }
  }

  /**
   * Returns `true` if the given role has ALL of the specified permissions.
   *
   * @throws {UnknownRoleError} If the role is not registered.
   * @throws {InvalidPermissionError} If any permission string is malformed.
   */
  canAll(role: string, permissions: string[]): boolean {
    return permissions.every((perm) => this.can(role, perm))
  }

  /**
   * Returns `true` if the given role has AT LEAST ONE of the specified permissions.
   *
   * @throws {UnknownRoleError} If the role is not registered.
   * @throws {InvalidPermissionError} If any permission string is malformed.
   */
  canAny(role: string, permissions: string[]): boolean {
    return permissions.some((perm) => this.can(role, perm))
  }

  /**
   * Asserts that the given role has ALL of the specified permissions.
   *
   * @throws {PermissionDeniedError} If the role lacks any permission.
   */
  assertAll(role: string, permissions: string[]): void {
    for (const perm of permissions) {
      if (!this.can(role, perm)) {
        throw new PermissionDeniedError(role, perm)
      }
    }
  }

  /**
   * Asserts that the given role has AT LEAST ONE of the specified permissions.
   *
   * @throws {PermissionDeniedError} If the role has none of the permissions.
   */
  assertAny(role: string, permissions: string[]): void {
    if (!this.canAny(role, permissions)) {
      throw new PermissionDeniedError(role, permissions.join(' | '))
    }
  }

  /**
   * Checks whether the given role has the specified permission and returns a
   * human-readable explanation of why the check passed or failed.
   *
   * @throws {UnknownRoleError} If the role is not registered.
   * @throws {InvalidPermissionError} If the permission string is malformed.
   */
  canWithReason(role: string, permission: string): PermissionCheckResult {
    if (!this.roles.has(role)) {
      throw new UnknownRoleError(role)
    }
    if (!validatePermission(permission)) {
      throw new InvalidPermissionError(permission)
    }

    const denied = this.denies.get(role)
    if (denied) {
      for (const deniedPerm of denied) {
        if (matchesPermission(permission, deniedPerm) || deniedPerm === permission) {
          return PolicyEngine.makeResult(false, `Permission "${permission}" is explicitly denied for role "${role}"`)
        }
      }
    }

    const roleDef = this.roles.get(role)!
    const maxLevel = roleDef.level

    // Collect eligible roles without .filter()/.sort() array allocations.
    // Two-pass: first collect, then sort in place.
    const eligible: RoleDefinition[] = []
    for (const r of this.roles.values()) {
      if (r.level <= maxLevel) eligible.push(r)
    }
    eligible.sort((a, b) => a.level - b.level)

    for (let si = 0; si < eligible.length; si++) {
      const source = eligible[si]
      const perms = source.permissions
      for (let pi = 0; pi < perms.length; pi++) {
        const pattern = perms[pi]
        if (matchesPermission(permission, pattern)) {
          const via = pattern !== permission ? ` via "${pattern}"` : ''
          const inherited = source.name !== role ? ` (inherited from "${source.name}")` : ''
          return PolicyEngine.makeResult(true, `Permission "${permission}" granted${via} to role "${source.name}"${inherited}`)
        }
      }
      if (source.groups) {
        for (let gi = 0; gi < source.groups.length; gi++) {
          const groupName = source.groups[gi]
          const groupPerms = this.groups.get(groupName)
          if (!groupPerms) continue
          for (let gpi = 0; gpi < groupPerms.length; gpi++) {
            const pattern = groupPerms[gpi]
            if (matchesPermission(permission, pattern)) {
              const via = pattern !== permission ? ` via "${pattern}"` : ''
              const inherited = source.name !== role ? ` (inherited from "${source.name}")` : ''
              return PolicyEngine.makeResult(true, `Permission "${permission}" granted${via} through group "${groupName}" on role "${source.name}"${inherited}`)
            }
          }
        }
      }
    }

    return PolicyEngine.makeResult(false, `No permission matching "${permission}" found for role "${role}"`)
  }

  // ---------------------------------------------------------------------------
  // Role introspection
  // ---------------------------------------------------------------------------

  /**
   * Returns the numeric level of the given role.
   *
   * @throws {UnknownRoleError} If the role is not registered.
   */
  getRoleLevel(role: string): number {
    const def = this.roles.get(role)
    if (!def) {
      throw new UnknownRoleError(role)
    }
    return def.level
  }

  /**
   * Returns `true` if the given role's level is greater than or equal to
   * the level of `minRole`.
   *
   * @throws {UnknownRoleError} If either role is not registered.
   */
  isAtLeast(role: string, minRole: string): boolean {
    return this.getRoleLevel(role) >= this.getRoleLevel(minRole)
  }

  /** Returns all registered role definitions. */
  listRoles(): RoleDefinition[] {
    return Array.from(this.roles.values()).map((r) => ({ ...r, permissions: [...r.permissions] }))
  }

  /**
   * Returns the full effective permission set for a role — all inherited
   * permissions and group expansions, minus any explicit denies.
   *
   * @throws {UnknownRoleError} If the role is not registered.
   */
  getPermissions(role: string): string[] {
    return Array.from(this.resolveEffectivePermissions(role))
  }

  /**
   * Serialises the current user's effective permission set into a compact
   * base64url string suitable for cookies, JWTs, and React props.
   *
   * The encoded string can be decoded client-side or in Edge middleware with
   * `fromBitmask()` from `permzplus/bitmask` — no engine import required.
   *
   * For multi-role arrays, the effective permissions are unioned before encoding.
   *
   * @param role - The role or array of roles to encode.
   * @returns A base64url string. Pass to `fromBitmask()` to decode.
   *
   * @example
   * ```ts
   * // At login — store in a signed cookie
   * const bitmask = policy.toBitmask(session.role)
   * res.cookie('permz', bitmask, { httpOnly: true, sameSite: 'strict' })
   *
   * // Multi-role
   * const bitmask = policy.toBitmask(['EDITOR', 'MODERATOR'])
   * ```
   */
  toBitmask(role: string | string[]): string {
    return _toBitmask(this, role)
  }

  // ---------------------------------------------------------------------------
  // Context creation
  // ---------------------------------------------------------------------------

  /**
   * Creates a short-lived `PermissionContext` bound to one or more roles.
   * When multiple roles are provided, `can` returns `true` if ANY satisfies
   * the check.
   *
   * @throws {UnknownRoleError} If any of the provided roles is not registered.
   */
  createContext(role: string | string[], opts?: Omit<ContextOptions, 'role' | 'roles'>): PermissionContext {
    const roles = Array.isArray(role) ? role : [role]
    for (const r of roles) {
      if (!this.roles.has(r)) {
        throw new UnknownRoleError(r)
      }
    }
    return new PermissionContext(roles, this, opts)
  }

  /**
   * Like `can()` but returns `false` instead of throwing for unknown or empty
   * roles. Safe to call for unauthenticated users. Accepts an optional subject
   * and context for ABAC condition evaluation.
   */
  safeCan(role: string, permission: string, subject?: unknown, ctx?: Record<string, unknown>): boolean {
    if (!role || !this.roles.has(role)) return false
    try {
      return this.can(role, permission, subject, ctx)
    } catch {
      return false
    }
  }

  /**
   * Like `createContext()` but returns a zero-permission context for unknown
   * or empty roles instead of throwing. Safe to use for unauthenticated users.
   */
  safeCreateContext(role: string | string[], opts?: Omit<ContextOptions, 'role' | 'roles'>): PermissionContext {
    const roles = Array.isArray(role) ? role : [role]
    const validRoles = roles.filter(r => r && this.roles.has(r))
    if (validRoles.length === 0) {
      return new PermissionContext([], this, opts)
    }
    return new PermissionContext(validRoles, this, opts)
  }

  /**
   * Returns the field names within `resource` that `role` is allowed to perform
   * `action` on. Looks for permissions in the format `resource.field:action`.
   *
   * @example
   * policy.addRole({ name: 'EDITOR', level: 1, permissions: ['post.title:edit', 'post.body:edit', 'post.status:read'] })
   * policy.permittedFieldsOf('EDITOR', 'post', 'edit') // → ['title', 'body']
   * policy.permittedFieldsOf('EDITOR', 'post', 'read') // → ['status']
   */
  permittedFieldsOf(role: string, resource: string, action: string): string[] {
    if (!role || !this.roles.has(role)) return []
    const prefix = `${resource}.`
    const suffix = `:${action}`
    const fields: string[] = []
    for (const perm of this.getPermissions(role)) {
      if (perm.startsWith(prefix) && perm.endsWith(suffix)) {
        const field = perm.slice(prefix.length, perm.length - suffix.length)
        if (field) fields.push(field)
      }
    }
    return fields
  }

  /**
   * Returns a copy of `obj` containing only the fields that `role` is allowed
   * to perform `action` on within `resource` (via `resource.field:action` permissions).
   *
   * @example
   * policy.addRole({ name: 'EDITOR', level: 1, permissions: ['post.title:read', 'post.body:read'] })
   * policy.filterFields('EDITOR', { title: 'hi', body: 'world', secret: 'x' }, 'post', 'read')
   * // → { title: 'hi', body: 'world' }
   */
  filterFields(role: string, obj: Record<string, unknown>, resource: string, action: string): Record<string, unknown> {
    const allowed = new Set(this.permittedFieldsOf(role, resource, action))
    const out: Record<string, unknown> = {}
    for (const k of Object.keys(obj)) if (allowed.has(k)) out[k] = obj[k]
    return out
  }

  /**
   * Creates a `PermissionContext` for a user by fetching their assigned roles
   * from the adapter. Roles that no longer exist in the engine are silently
   * filtered out (stale assignment data).
   *
   * Requires an adapter with user-role support (`assignRole` / `getUserRoles`).
   *
   * @throws {AdapterError} If no adapter is configured or it lacks user-role methods.
   */
  async createUserContext(
    userId: string,
    tenantId?: string,
    opts?: Omit<ContextOptions, 'role' | 'roles' | 'userId' | 'tenantId'>,
  ): Promise<PermissionContext> {
    const adapter = this.requireUserAdapter()
    const allRoles = await adapter.getUserRoles(userId, tenantId)
    const validRoles = allRoles.filter((r) => this.roles.has(r))
    return new PermissionContext(validRoles, this, { ...opts, userId, tenantId })
  }

  /**
   * Creates a `PermissionContext` representing `targetRoles` acting on behalf
   * of a delegating principal. If `scope` is provided, the context only grants
   * permissions that are in the scope AND held by `targetRoles`.
   *
   * @throws {UnknownRoleError} If any of the provided roles is not registered.
   */
  delegate(
    targetRoles: string | string[],
    opts?: DelegateOptions & Omit<ContextOptions, 'role' | 'roles'>,
  ): PermissionContext {
    const roles = Array.isArray(targetRoles) ? targetRoles : [targetRoles]
    for (const r of roles) {
      if (!this.roles.has(r)) throw new UnknownRoleError(r)
    }

    if (opts?.scope !== undefined) {
      return new ScopedPermissionContext(roles, this, opts.scope, opts)
    }

    return new PermissionContext(roles, this, opts)
  }

  /**
   * Async variant of `delegate()` that fetches the target user's roles from the
   * adapter before creating the delegated context.
   *
   * @throws {AdapterError} If no adapter is configured or it lacks user-role methods.
   */
  async delegateUser(
    userId: string,
    tenantId?: string,
    opts?: DelegateOptions & Omit<ContextOptions, 'role' | 'roles' | 'userId' | 'tenantId'>,
  ): Promise<PermissionContext> {
    const adapter = this.requireUserAdapter()
    const allRoles = await adapter.getUserRoles(userId, tenantId)
    const validRoles = allRoles.filter((r) => this.roles.has(r))
    return this.delegate(validRoles, { ...opts, userId, tenantId })
  }

  // ---------------------------------------------------------------------------
  // Role mutation API
  // ---------------------------------------------------------------------------

  /**
   * Registers a new role (or replaces an existing one). All permissions in the
   * role definition are validated before storage.
   *
   * @throws {InvalidPermissionError} If any permission string in the role is malformed.
   * @returns `this` for chaining.
   */
  addRole(role: RoleDefinition): this {
    for (const perm of role.permissions) {
      if (!validatePermission(perm)) {
        throw new InvalidPermissionError(perm)
      }
    }

    this.roles.set(role.name, { ...role, permissions: [...role.permissions] })
    this.invalidateCache()
    this.hooks.onRoleAdd?.(role)
    this.fireAudit({ action: 'role.add', role: role.name })

    this.fireAndForget(this.adapter?.saveRole(role), 'saveRole')
    for (const perm of role.permissions) {
      this.fireAndForget(this.adapter?.grantPermission(role.name, perm), 'grantPermission')
    }

    return this
  }

  /**
   * Removes a role from the engine.
   *
   * @throws {UnknownRoleError} If the role is not registered.
   * @returns `this` for chaining.
   */
  removeRole(role: string): this {
    if (!this.roles.has(role)) {
      throw new UnknownRoleError(role)
    }

    this.roles.delete(role)
    this.denies.delete(role)
    this.invalidateCache()
    this.hooks.onRoleRemove?.(role)
    this.fireAudit({ action: 'role.remove', role })

    this.fireAndForget(this.adapter?.deleteRole(role), 'deleteRole')

    return this
  }

  /**
   * Grants an additional permission to an existing role.
   *
   * @throws {UnknownRoleError} If the role is not registered.
   * @throws {InvalidPermissionError} If the permission string is malformed.
   * @returns `this` for chaining.
   */
  grantTo(role: string, permission: string): this {
    const def = this.roles.get(role)
    if (!def) {
      throw new UnknownRoleError(role)
    }
    if (!validatePermission(permission)) {
      throw new InvalidPermissionError(permission)
    }

    const existing = new Set(def.permissions)
    if (!existing.has(permission)) {
      def.permissions.push(permission)
    }

    this.invalidateCache()
    this.hooks.onGrant?.(role, permission)
    this.fireAudit({ action: 'permission.grant', role, permission })
    this.fireAndForget(this.adapter?.grantPermission(role, permission), 'grantPermission')

    return this
  }

  /**
   * Revokes a previously granted permission from a role's own permission list.
   * Does not affect permissions inherited from lower-level roles.
   * This is a no-op if the role does not directly have the permission.
   *
   * @throws {UnknownRoleError} If the role is not registered.
   * @throws {InvalidPermissionError} If the permission string is malformed.
   * @returns `this` for chaining.
   */
  revokeFrom(role: string, permission: string): this {
    const def = this.roles.get(role)
    if (!def) {
      throw new UnknownRoleError(role)
    }
    if (!validatePermission(permission)) {
      throw new InvalidPermissionError(permission)
    }

    def.permissions = def.permissions.filter((p) => p !== permission)
    this.invalidateCache()
    this.hooks.onRevoke?.(role, permission)
    this.fireAudit({ action: 'permission.revoke', role, permission })
    this.fireAndForget(this.adapter?.revokePermission(role, permission), 'revokePermission')

    return this
  }

  /**
   * Explicitly denies a permission for a role, overriding any inherited grant.
   * The deny list is per-role and is not inherited by higher-level roles.
   *
   * @throws {UnknownRoleError} If the role is not registered.
   * @throws {InvalidPermissionError} If the permission string is malformed.
   * @returns `this` for chaining.
   */
  denyFrom(role: string, permission: string): this {
    if (!this.roles.has(role)) {
      throw new UnknownRoleError(role)
    }
    if (!validatePermission(permission)) {
      throw new InvalidPermissionError(permission)
    }

    if (!this.denies.has(role)) {
      this.denies.set(role, new Set())
    }
    this.denies.get(role)!.add(permission)

    this.permCache.delete(role)
    this.permBitsCache.delete(role)
    this.checkCache.delete(role)
    this.hooks.onDeny?.(role, permission)
    this.fireAudit({ action: 'permission.deny', role, permission })
    this.fireAndForget(this.adapter?.saveDeny(role, permission), 'saveDeny')

    return this
  }

  /**
   * Removes an explicit deny for a role+permission pair, restoring normal
   * inheritance behaviour. No-op if no such deny exists.
   *
   * @throws {UnknownRoleError} If the role is not registered.
   * @throws {InvalidPermissionError} If the permission string is malformed.
   * @returns `this` for chaining.
   */
  removeDeny(role: string, permission: string): this {
    if (!this.roles.has(role)) {
      throw new UnknownRoleError(role)
    }
    if (!validatePermission(permission)) {
      throw new InvalidPermissionError(permission)
    }

    this.denies.get(role)?.delete(permission)
    this.permCache.delete(role)
    this.permBitsCache.delete(role)
    this.checkCache.delete(role)
    this.hooks.onRemoveDeny?.(role, permission)
    this.fireAudit({ action: 'permission.removeDeny', role, permission })
    this.fireAndForget(this.adapter?.removeDeny(role, permission), 'removeDeny')

    return this
  }

  // ---------------------------------------------------------------------------
  // User-role assignment (requires adapter with user-role support)
  // ---------------------------------------------------------------------------

  /**
   * Assigns a role to a user. When `tenantId` is provided the assignment is
   * scoped to that tenant.
   *
   * @throws {UnknownRoleError} If `roleName` is not registered in the engine.
   * @throws {AdapterError} If no adapter is configured or it lacks user-role support.
   */
  async assignRole(userId: string, roleName: string, tenantId?: string, options?: { expiresAt?: Date }): Promise<void> {
    if (!this.roles.has(roleName)) {
      throw new UnknownRoleError(roleName)
    }
    const adapter = this.requireUserAdapter()
    await adapter.assignRole(userId, roleName, tenantId, options)
    this.fireAudit({ action: 'user.assignRole', role: roleName, userId, tenantId })
  }

  /**
   * Revokes a role from a user.
   *
   * @throws {AdapterError} If no adapter is configured or it lacks user-role support.
   */
  async revokeRole(userId: string, roleName: string, tenantId?: string): Promise<void> {
    const adapter = this.requireUserAdapter()
    await adapter.revokeRole(userId, roleName, tenantId)
    this.fireAudit({ action: 'user.revokeRole', role: roleName, userId, tenantId })
  }

  /**
   * Returns all role names currently assigned to a user. Optionally filtered
   * by `tenantId` for multi-tenant setups.
   *
   * @throws {AdapterError} If no adapter is configured or it lacks user-role support.
   */
  async getUserRoles(userId: string, tenantId?: string): Promise<string[]> {
    const adapter = this.requireUserAdapter()
    return adapter.getUserRoles(userId, tenantId)
  }

  /**
   * Checks whether a user has the given permission across any of their
   * assigned roles. Roles that no longer exist in the engine are ignored.
   *
   * @throws {AdapterError} If no adapter is configured or it lacks user-role support.
   * @throws {InvalidPermissionError} If the permission string is malformed.
   */
  async canUser(userId: string, permission: string, tenantId?: string): Promise<boolean> {
    if (!validatePermission(permission)) {
      throw new InvalidPermissionError(permission)
    }
    const adapter = this.requireUserAdapter()
    const roles = await adapter.getUserRoles(userId, tenantId)
    return roles.some((r) => this.roles.has(r) && this.can(r, permission))
  }

  // ---------------------------------------------------------------------------
  // Bulk mutation API
  // ---------------------------------------------------------------------------

  /**
   * Registers multiple roles at once. Each role is validated and added
   * individually, so the first invalid role will throw without rolling back
   * previously added roles in the same call.
   *
   * @returns `this` for chaining.
   */
  addRoles(roles: RoleDefinition[]): this {
    for (const role of roles) {
      this.addRole(role)
    }
    return this
  }

  /**
   * Grants multiple permissions to a role in a single operation.
   * The permission cache is invalidated once after all grants are applied.
   *
   * @throws {UnknownRoleError} If the role is not registered.
   * @throws {InvalidPermissionError} If any permission string is malformed.
   * @returns `this` for chaining.
   */
  grantBulk(role: string, permissions: string[]): this {
    const def = this.roles.get(role)
    if (!def) throw new UnknownRoleError(role)
    for (const permission of permissions) {
      if (!validatePermission(permission)) throw new InvalidPermissionError(permission)
    }
    const existing = new Set(def.permissions)
    for (const permission of permissions) {
      if (!existing.has(permission)) {
        def.permissions.push(permission)
        existing.add(permission)
      }
      this.hooks.onGrant?.(role, permission)
      this.fireAudit({ action: 'permission.grant', role, permission })
      this.fireAndForget(this.adapter?.grantPermission(role, permission), 'grantPermission')
    }
    this.invalidateCache()
    return this
  }

  /**
   * Revokes multiple permissions from a role in a single operation.
   * Only removes permissions from the role's own list — inherited permissions
   * are unaffected.
   *
   * @throws {UnknownRoleError} If the role is not registered.
   * @throws {InvalidPermissionError} If any permission string is malformed.
   * @returns `this` for chaining.
   */
  revokeBulk(role: string, permissions: string[]): this {
    const def = this.roles.get(role)
    if (!def) throw new UnknownRoleError(role)
    for (const permission of permissions) {
      if (!validatePermission(permission)) throw new InvalidPermissionError(permission)
    }
    const toRemove = new Set(permissions)
    def.permissions = def.permissions.filter((p) => !toRemove.has(p))
    this.invalidateCache()
    for (const permission of permissions) {
      this.hooks.onRevoke?.(role, permission)
      this.fireAudit({ action: 'permission.revoke', role, permission })
      this.fireAndForget(this.adapter?.revokePermission(role, permission), 'revokePermission')
    }
    return this
  }

  /**
   * Explicitly denies multiple permissions for a role in a single operation.
   *
   * @throws {UnknownRoleError} If the role is not registered.
   * @throws {InvalidPermissionError} If any permission string is malformed.
   * @returns `this` for chaining.
   */
  denyBulk(role: string, permissions: string[]): this {
    if (!this.roles.has(role)) throw new UnknownRoleError(role)
    for (const permission of permissions) {
      if (!validatePermission(permission)) throw new InvalidPermissionError(permission)
    }
    if (!this.denies.has(role)) this.denies.set(role, new Set())
    const denySet = this.denies.get(role)!
    for (const permission of permissions) {
      denySet.add(permission)
      this.hooks.onDeny?.(role, permission)
      this.fireAudit({ action: 'permission.deny', role, permission })
      this.fireAndForget(this.adapter?.saveDeny(role, permission), 'saveDeny')
    }
    this.permCache.delete(role)
    return this
  }

  /**
   * Assigns multiple roles to a user in a single operation.
   * Roles that are not registered in the engine will throw `UnknownRoleError`
   * before any assignments are made.
   *
   * @throws {UnknownRoleError} If any role name is not registered.
   * @throws {AdapterError} If no adapter is configured or it lacks user-role support.
   */
  async assignRoles(userId: string, roleNames: string[], tenantId?: string): Promise<void> {
    for (const roleName of roleNames) {
      if (!this.roles.has(roleName)) throw new UnknownRoleError(roleName)
    }
    const adapter = this.requireUserAdapter()
    for (const roleName of roleNames) {
      await adapter.assignRole(userId, roleName, tenantId)
      this.fireAudit({ action: 'user.assignRole', role: roleName, userId, tenantId })
    }
  }

  /**
   * Revokes multiple roles from a user in a single operation.
   *
   * @throws {AdapterError} If no adapter is configured or it lacks user-role support.
   */
  async revokeRoles(userId: string, roleNames: string[], tenantId?: string): Promise<void> {
    const adapter = this.requireUserAdapter()
    for (const roleName of roleNames) {
      await adapter.revokeRole(userId, roleName, tenantId)
      this.fireAudit({ action: 'user.revokeRole', role: roleName, userId, tenantId })
    }
  }

  // ---------------------------------------------------------------------------
  // Serialisation / deserialisation
  // ---------------------------------------------------------------------------

  /**
   * Serialises the current in-memory policy state to a plain object.
   * Pass the result to `PolicyEngine.fromJSON()` to reconstruct an identical
   * engine. The adapter reference and hooks are NOT included.
   */
  toJSON(): PolicySnapshot {
    const denies: Record<string, string[]> = {}
    for (const [role, set] of this.denies) {
      denies[role] = Array.from(set)
    }

    const groups: Record<string, string[]> = {}
    for (const [name, perms] of this.groups) {
      groups[name] = [...perms]
    }

    return {
      roles: this.listRoles(),
      denies,
      groups,
    }
  }

  /**
   * Reconstructs a `PolicyEngine` from a snapshot produced by `toJSON()`.
   * The resulting engine is in-memory only — no adapter is attached.
   */
  static fromJSON(snapshot: PolicySnapshot): PolicyEngine {
    const engine = new PolicyEngine({ roles: snapshot.roles })

    for (const [name, perms] of Object.entries(snapshot.groups)) {
      engine.groups.set(name, [...perms])
    }

    for (const [role, perms] of Object.entries(snapshot.denies)) {
      engine.denies.set(role, new Set(perms))
    }

    return engine
  }

  /**
   * Creates a `PolicyEngine` backed by a persistent adapter. All roles, their
   * permissions, and any explicit denies are loaded from the adapter.
   *
   * @param adapter - A `PermzAdapter` implementation.
   * @returns A fully initialised `PolicyEngine` instance.
   */
  static async fromAdapter(adapter: PermzAdapter): Promise<PolicyEngine> {
    const engine = new PolicyEngine()
    engine.adapter = adapter

    const allRoles = await adapter.getRoles()

    for (const role of allRoles) {
      const perms = await adapter.getPermissions(role.name)
      engine.roles.set(role.name, {
        ...role,
        permissions: perms.length ? perms : role.permissions,
      })

      const denied = await adapter.getDeniedPermissions(role.name)
      if (denied.length) {
        engine.denies.set(role.name, new Set(denied))
      }
    }

    return engine
  }

  /**
   * Parses a CSV string into a `PolicyEngine`. The first row may optionally be
   * a header row (`role,level,permissions,groups`) — it is detected and skipped
   * automatically.
   */
  static fromCSV(csv: string, opts?: PolicyOptions): PolicyEngine {
    const lines = csv.trim().split('\n').map(l => l.trim()).filter(Boolean)
    if (lines.length === 0) return new PolicyEngine(opts)

    const isHeader = /^role[,\s]/i.test(lines[0])
    const dataLines = isHeader ? lines.slice(1) : lines

    const roles: RoleDefinition[] = dataLines.map(line => {
      const cols = parseCSVLine(line)
      const name = cols[0]?.trim() ?? ''
      const level = parseInt(cols[1] ?? '0', 10)
      const permissions = (cols[2] ?? '').split(',').map(p => p.trim()).filter(Boolean)
      const groups = (cols[3] ?? '').split(',').map(g => g.trim()).filter(Boolean)
      return { name, level, permissions, ...(groups.length ? { groups } : {}) }
    })

    return new PolicyEngine({ ...opts, roles })
  }

  /**
   * Serialises the current in-memory policy state to a CSV string.
   * The first row is a header row: `role,level,permissions,groups`.
   */
  toCSV(): string {
    const header = 'role,level,permissions,groups'
    const rows = this.listRoles().map(r => {
      const perms = r.permissions.join(',')
      const groups = (r.groups ?? []).join(',')
      return `${r.name},${r.level},"${perms}","${groups}"`
    })
    return [header, ...rows].join('\n')
  }

  /**
   * Constructs a `PolicyEngine` from a bulk JSON payload. Accepts either:
   * - A `RoleDefinition[]` array
   * - A `PolicySnapshot` object (same shape as `toJSON()`)
   *
   * The argument may be a raw JSON string or an already-parsed object.
   */
  static fromBulkJSON(json: string | object, opts?: PolicyOptions): PolicyEngine {
    const data = typeof json === 'string' ? JSON.parse(json) : json
    if (Array.isArray(data)) {
      return new PolicyEngine({ ...opts, roles: data as RoleDefinition[] })
    }
    // Assume PolicySnapshot shape
    const engine = PolicyEngine.fromJSON(data as PolicySnapshot)
    return engine
  }
}
