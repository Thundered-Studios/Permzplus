/**
 * React integration for Permzplus.
 *
 * Peer dependency: `react` >= 18
 *
 * @example
 * ```tsx
 * import { PermissionProvider, usePermission, Can } from 'permzplus/react'
 *
 * // Wrap your app (or a subtree) with the provider
 * function App() {
 *   return (
 *     <PermissionProvider engine={policy} role={user.role}>
 *       <Dashboard />
 *     </PermissionProvider>
 *   )
 * }
 *
 * // Use the hook anywhere in the tree
 * function DeleteButton() {
 *   const canDelete = usePermission('posts:delete')
 *   return canDelete ? <button>Delete</button> : null
 * }
 *
 * // Or use the declarative component
 * function Toolbar() {
 *   return (
 *     <Can permission="posts:delete" fallback={<span>No access</span>}>
 *       <DeleteButton />
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
  /** The role (or roles) for the current user. */
  role: string | string[]
  children: ReactNode
}

/**
 * Provides a `PolicyEngine` and the current user's role(s) to all descendant
 * hooks and components.
 *
 * When `role` is an array, permission checks pass if ANY role satisfies them.
 */
export function PermissionProvider({ engine, role, children }: PermissionProviderProps): ReactNode {
  return createElement(PermissionCtx.Provider, { value: { engine, role } }, children)
}

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

/**
 * Returns `true` if the current user's role(s) have the given permission.
 * An optional `condition` function adds resource-level logic on top of the
 * role check — both must pass for the hook to return `true`.
 *
 * @example
 * const canEdit = usePermission('posts:edit', () => post.authorId === userId)
 */
export function usePermission(permission: string, condition?: () => boolean): boolean {
  const { engine, role } = usePermissionState()
  const roles = Array.isArray(role) ? role : [role]
  const hasPermission = roles.some((r) => engine.can(r, permission))
  if (!hasPermission) return false
  if (condition !== undefined) return condition()
  return true
}

/** Alias for `usePermission`. */
export const useCan = usePermission

/**
 * Returns `true` if the current user's role(s) have ALL of the given permissions.
 */
export function useCanAll(permissions: string[], condition?: () => boolean): boolean {
  const { engine, role } = usePermissionState()
  const roles = Array.isArray(role) ? role : [role]
  const allPass = roles.some((r) => engine.canAll(r, permissions))
  if (!allPass) return false
  if (condition !== undefined) return condition()
  return true
}

/**
 * Returns `true` if the current user's role(s) have AT LEAST ONE of the given permissions.
 */
export function useCanAny(permissions: string[], condition?: () => boolean): boolean {
  const { engine, role } = usePermissionState()
  const roles = Array.isArray(role) ? role : [role]
  const anyPass = roles.some((r) => engine.canAny(r, permissions))
  if (!anyPass) return false
  if (condition !== undefined) return condition()
  return true
}

// ---------------------------------------------------------------------------
// Declarative components
// ---------------------------------------------------------------------------

export interface CanProps {
  permission: string
  condition?: () => boolean
  children: ReactNode
  /** Rendered when the check fails. Defaults to `null`. */
  fallback?: ReactNode
}

/**
 * Renders `children` when the current user has the given permission, otherwise
 * renders `fallback` (default: nothing).
 *
 * @example
 * <Can permission="posts:delete" fallback={<span>Read-only</span>}>
 *   <DeleteButton />
 * </Can>
 */
export function Can({ permission, condition, children, fallback = null }: CanProps): ReactNode {
  const can = usePermission(permission, condition)
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
