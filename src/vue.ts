/**
 * Vue 3 integration for Permzplus.
 *
 * Peer dependency: `vue` >= 3
 *
 * @example
 * ```ts
 * // In your root component or plugin:
 * import { providePermissions } from 'permzplus/vue'
 *
 * // app.vue / setup()
 * providePermissions(policy, user.role)
 *
 * // In any child component:
 * import { usePermission } from 'permzplus/vue'
 *
 * const canDelete = usePermission('posts:delete')
 * // canDelete is a ComputedRef<boolean>
 * ```
 */

import { computed, inject, provide, type ComputedRef, type InjectionKey } from 'vue'
import type { IPolicyEngine } from './types'

// ---------------------------------------------------------------------------
// Internal state type
// ---------------------------------------------------------------------------

interface PermissionState {
  engine: IPolicyEngine
  role: string | string[]
}

const PERMZ_KEY: InjectionKey<PermissionState> = Symbol('permzplus')

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

/**
 * Provides a `PolicyEngine` and the current user's role(s) to all descendant
 * components. Call this in a parent component's `setup()` — typically your
 * root `App.vue` or a layout component.
 *
 * When `role` is an array, permission checks pass if ANY role satisfies them.
 *
 * @example
 * ```ts
 * // App.vue
 * import { providePermissions } from 'permzplus/vue'
 * providePermissions(policy, currentUser.role)
 * ```
 */
export function providePermissions(engine: IPolicyEngine, role: string | string[]): void {
  provide(PERMZ_KEY, { engine, role })
}

function usePermissionState(): PermissionState {
  const state = inject(PERMZ_KEY)
  if (!state) {
    throw new Error(
      '[permzplus] usePermission must be called inside a component where providePermissions() has been called.',
    )
  }
  return state
}

// ---------------------------------------------------------------------------
// Composables
// ---------------------------------------------------------------------------

/**
 * Returns a `ComputedRef<boolean>` that is `true` when the current user's
 * role(s) have the given permission. Re-evaluates reactively if `role` changes.
 *
 * An optional `condition` function adds resource-level logic — both must pass.
 *
 * @example
 * ```ts
 * const canEdit = usePermission('posts:edit', () => post.value.authorId === userId.value)
 * ```
 */
export function usePermission(
  permission: string,
  condition?: () => boolean,
): ComputedRef<boolean> {
  const state = usePermissionState()
  return computed(() => {
    const roles = Array.isArray(state.role) ? state.role : [state.role]
    const hasPermission = roles.some((r) => state.engine.can(r, permission))
    if (!hasPermission) return false
    if (condition !== undefined) return condition()
    return true
  })
}

/** Alias for `usePermission`. */
export const useCan = usePermission

/**
 * Returns a `ComputedRef<boolean>` that is `true` when the current user's
 * role(s) have ALL of the given permissions.
 */
export function useCanAll(
  permissions: string[],
  condition?: () => boolean,
): ComputedRef<boolean> {
  const state = usePermissionState()
  return computed(() => {
    const roles = Array.isArray(state.role) ? state.role : [state.role]
    const allPass = roles.some((r) => state.engine.canAll(r, permissions))
    if (!allPass) return false
    if (condition !== undefined) return condition()
    return true
  })
}

/**
 * Returns a `ComputedRef<boolean>` that is `true` when the current user's
 * role(s) have AT LEAST ONE of the given permissions.
 */
export function useCanAny(
  permissions: string[],
  condition?: () => boolean,
): ComputedRef<boolean> {
  const state = usePermissionState()
  return computed(() => {
    const roles = Array.isArray(state.role) ? state.role : [state.role]
    const anyPass = roles.some((r) => state.engine.canAny(r, permissions))
    if (!anyPass) return false
    if (condition !== undefined) return condition()
    return true
  })
}
