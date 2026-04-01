/**
 * React integration for Permzplus.
 *
 * Peer dependency: `react` >= 18
 *
 * @example
 * ```tsx
 * import { PermissionProvider, usePermission, useAbility, Can, CanI } from 'permzplus/react'
 *
 * // Wrap your app (or a subtree) with the provider
 * function App() {
 *   return (
 *     <PermissionProvider engine={policy} role={user.role ?? ''}>
 *       <Dashboard />
 *     </PermissionProvider>
 *   )
 * }
 *
 * // Hook — single permission
 * function DeleteButton() {
 *   const canDelete = usePermission('posts:delete')
 *   return canDelete ? <button>Delete</button> : null
 * }
 *
 * // Hook — stable ability object (like CASL's useAbility)
 * function EditButton({ post, userId }) {
 *   const ability = useAbility()
 *   if (!ability.can('posts:edit', () => post.authorId === userId)) return null
 *   return <button>Edit</button>
 * }
 *
 * // Declarative — permission string
 * function Toolbar() {
 *   return (
 *     <Can permission="posts:delete" fallback={<span>No access</span>}>
 *       <DeleteButton />
 *     </Can>
 *   )
 * }
 *
 * // Declarative — CASL-style I/a props (maps to resource:action)
 * function EditForm() {
 *   return (
 *     <Can I="edit" a="post">
 *       <PostEditor />
 *     </Can>
 *   )
 * }
 * ```
 */

import { createContext, useContext, createElement, type ReactNode } from 'react'
import type { IPolicyEngine } from './types'

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

interface PermissionState {
  engine: IPolicyEngine
  role: string | string[]
}

const PermissionCtx = createContext<PermissionState | null>(null)

function usePermissionState(): PermissionState {
  const ctx = useContext(PermissionCtx)
  if (!ctx) {
    throw new Error(
      '[permzplus] usePermission / Can must be used inside a <PermissionProvider>.',
    )
  }
  return ctx
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

export interface PermissionProviderProps {
  engine: IPolicyEngine
  /** The role (or roles) for the current user. Pass an empty string for unauthenticated users. */
  role: string | string[]
  children: ReactNode
}

/**
 * Provides a `PolicyEngine` and the current user's role(s) to all descendant
 * hooks and components.
 *
 * When `role` is an array, permission checks pass if ANY role satisfies them.
 * Pass an empty string (`''`) for unauthenticated users — all checks will
 * safely return `false` without throwing.
 */
export function PermissionProvider({ engine, role, children }: PermissionProviderProps): ReactNode {
  return createElement(PermissionCtx.Provider, { value: { engine, role } }, children)
}

// ---------------------------------------------------------------------------
// Ability interface & hook
// ---------------------------------------------------------------------------

/**
 * Stable ability object returned by `useAbility()`. Mirrors the
 * `PermissionContext` API but is safe for unauthenticated (empty) roles.
 */
export interface Ability {
  /** Current role(s) bound to the provider. */
  role: string | string[]
  /** The underlying PolicyEngine. */
  engine: IPolicyEngine
  /**
   * Returns `true` if the current role has the given permission.
   * Returns `false` for unknown or empty roles instead of throwing.
   */
  can(permission: string, condition?: () => boolean): boolean
  /** Returns `true` if the current role does NOT have the given permission. */
  cannot(permission: string, condition?: () => boolean): boolean
  /** Returns `true` if the current role has ALL of the given permissions. */
  canAll(permissions: string[], condition?: () => boolean): boolean
  /** Returns `true` if the current role has ANY of the given permissions. */
  canAny(permissions: string[], condition?: () => boolean): boolean
}

/**
 * Returns a stable `Ability` object for the current user, analogous to
 * CASL's `useAbility()`. All permission checks are null-safe — unknown or
 * empty roles return `false` instead of throwing.
 *
 * @example
 * const ability = useAbility()
 * ability.can('posts:edit')
 * ability.can('posts:edit', () => post.authorId === userId)
 * ability.canAll(['content:read', 'content:create'])
 */
export function useAbility(): Ability {
  const { engine, role } = usePermissionState()
  const roles = Array.isArray(role) ? role : [role]

  const safeCheck = (r: string, perm: string): boolean => {
    try { return engine.can(r, perm) } catch { return false }
  }

  return {
    role,
    engine,
    can(permission: string, condition?: () => boolean): boolean {
      try {
        const hasPermission = roles.some((r) => safeCheck(r, permission))
        if (!hasPermission) return false
        return condition !== undefined ? condition() : true
      } catch { return false }
    },
    cannot(permission: string, condition?: () => boolean): boolean {
      return !this.can(permission, condition)
    },
    canAll(permissions: string[], condition?: () => boolean): boolean {
      try {
        const allPass = roles.some((r) => {
          try { return engine.canAll(r, permissions) } catch { return false }
        })
        if (!allPass) return false
        return condition !== undefined ? condition() : true
      } catch { return false }
    },
    canAny(permissions: string[], condition?: () => boolean): boolean {
      try {
        const anyPass = roles.some((r) => {
          try { return engine.canAny(r, permissions) } catch { return false }
        })
        if (!anyPass) return false
        return condition !== undefined ? condition() : true
      } catch { return false }
    },
  }
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

/**
 * Returns `true` if the current user's role(s) have the given permission.
 * An optional `condition` function adds resource-level logic on top of the
 * role check — both must pass for the hook to return `true`.
 *
 * Safe for unauthenticated users (empty or unknown roles return `false`).
 *
 * @example
 * const canEdit = usePermission('posts:edit', () => post.authorId === userId)
 */
export function usePermission(permission: string, condition?: () => boolean): boolean {
  const { engine, role } = usePermissionState()
  const roles = Array.isArray(role) ? role : [role]
  let hasPermission = false
  try {
    hasPermission = roles.some((r) => { try { return engine.can(r, permission) } catch { return false } })
  } catch { return false }
  if (!hasPermission) return false
  if (condition !== undefined) return condition()
  return true
}

/** Alias for `usePermission`. */
export const useCan = usePermission

/**
 * Returns `true` if the current user's role(s) have ALL of the given permissions.
 * Safe for unauthenticated users.
 */
export function useCanAll(permissions: string[], condition?: () => boolean): boolean {
  const { engine, role } = usePermissionState()
  const roles = Array.isArray(role) ? role : [role]
  let allPass = false
  try {
    allPass = roles.some((r) => { try { return engine.canAll(r, permissions) } catch { return false } })
  } catch { return false }
  if (!allPass) return false
  if (condition !== undefined) return condition()
  return true
}

/**
 * Returns `true` if the current user's role(s) have AT LEAST ONE of the given permissions.
 * Safe for unauthenticated users.
 */
export function useCanAny(permissions: string[], condition?: () => boolean): boolean {
  const { engine, role } = usePermissionState()
  const roles = Array.isArray(role) ? role : [role]
  let anyPass = false
  try {
    anyPass = roles.some((r) => { try { return engine.canAny(r, permissions) } catch { return false } })
  } catch { return false }
  if (!anyPass) return false
  if (condition !== undefined) return condition()
  return true
}

// ---------------------------------------------------------------------------
// Declarative components
// ---------------------------------------------------------------------------

export interface CanProps {
  permission?: string
  /**
   * CASL-style action prop. Use together with `a` (or `an`/`this`) to form
   * a `resource:action` permission check.
   *
   * @example <Can I="edit" a="post">...</Can>
   */
  I?: string
  /**
   * CASL-style subject/resource prop. Used with `I` to form `resource:action`.
   * Case-insensitive — `Post` and `post` both map to `post:action`.
   */
  a?: string
  /** Alias for `a`. */
  an?: string
  condition?: () => boolean
  children: ReactNode
  /** Rendered when the check fails. Defaults to `null`. */
  fallback?: ReactNode
}

/**
 * Renders `children` when the current user has the given permission.
 *
 * Supports two usage patterns:
 *
 * 1. **Explicit permission string** — classic PermzPlus style:
 *    ```tsx
 *    <Can permission="posts:delete" fallback={<span>Read-only</span>}>
 *      <DeleteButton />
 *    </Can>
 *    ```
 *
 * 2. **CASL-style I/a props** — maps `a:action` → `resource:action`:
 *    ```tsx
 *    <Can I="edit" a="post">
 *      <EditButton />
 *    </Can>
 *    ```
 *    Equivalent to `can('post:edit')`.
 */
export function Can({ permission, I: action, a, an, condition, children, fallback = null }: CanProps): ReactNode {
  let resolvedPermission: string
  if (permission) {
    resolvedPermission = permission
  } else if (action) {
    const resource = (a ?? an ?? '').toLowerCase()
    resolvedPermission = resource ? `${resource}:${action}` : action
  } else {
    return fallback
  }
  const can = usePermission(resolvedPermission, condition)
  return can ? children : fallback
}

export interface CanAllProps {
  permissions: string[]
  condition?: () => boolean
  children: ReactNode
  fallback?: ReactNode
}

/**
 * Renders `children` when the current user has ALL of the given permissions.
 */
export function CanAll({ permissions, condition, children, fallback = null }: CanAllProps): ReactNode {
  const can = useCanAll(permissions, condition)
  return can ? children : fallback
}

export interface CanAnyProps {
  permissions: string[]
  condition?: () => boolean
  children: ReactNode
  fallback?: ReactNode
}

/**
 * Renders `children` when the current user has AT LEAST ONE of the given permissions.
 */
export function CanAny({ permissions, condition, children, fallback = null }: CanAnyProps): ReactNode {
  const can = useCanAny(permissions, condition)
  return can ? children : fallback
}
