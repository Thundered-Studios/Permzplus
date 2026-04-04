'use client'

/**
 * Next.js App Router — Client-side hooks and components for Permzplus.
 *
 * Import from `permzplus/nextjs/client` in Client Components.
 * The `'use client'` directive at the top of this file marks it as a
 * client module boundary — all exports run only in the browser.
 *
 * **Typical flow:**
 * 1. Server Component / Server Action calls `getPermissionMap(engine, role)`
 *    and passes the result (or just `permMap.bitmask`) as a prop.
 * 2. A root Client Component wraps its subtree with `<PermissionBitmaskProvider>`.
 * 3. Descendant Client Components call `usePermissions()` or use `<CanClient>`
 *    — all checks run locally in the browser without contacting the server.
 *
 * @example Provider setup
 * ```tsx
 * // components/ClientLayout.tsx
 * 'use client'
 * import { PermissionBitmaskProvider } from 'permzplus/nextjs/client'
 *
 * export function ClientLayout({ bitmask, children }) {
 *   return (
 *     <PermissionBitmaskProvider bitmask={bitmask}>
 *       {children}
 *     </PermissionBitmaskProvider>
 *   )
 * }
 * ```
 *
 * @example Hook usage
 * ```tsx
 * 'use client'
 * import { usePermissions } from 'permzplus/nextjs/client'
 *
 * // Reads from PermissionBitmaskProvider — no bitmask prop needed
 * export function DeleteButton() {
 *   const perms = usePermissions()
 *   if (perms.cannot('posts:delete')) return null
 *   return <button>Delete</button>
 * }
 * ```
 *
 * @example Inline hook (no provider required)
 * ```tsx
 * // Pass the bitmask directly when you don't have a provider set up
 * const perms = usePermissions(bitmask)
 * ```
 *
 * @example CanClient component
 * ```tsx
 * <CanClient permission="posts:delete" fallback={<span>Read-only</span>}>
 *   <DeleteButton />
 * </CanClient>
 * ```
 */

import {
  createContext,
  useContext,
  useMemo,
  createElement,
  type ReactNode,
} from 'react'
import { fromBitmask, type PermissionBitmask } from './bitmask'

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

const BitmaskCtx = createContext<PermissionBitmask | null>(null)

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

export interface PermissionBitmaskProviderProps {
  /**
   * The base64url bitmask string from `getPermissionMap(engine, role).bitmask`
   * or `toBitmask(engine, role)`. Decoded once on mount and whenever it changes.
   */
  bitmask: string
  children: ReactNode
}

/**
 * Decodes the `bitmask` prop once and makes the resulting `PermissionBitmask`
 * available to all `usePermissions()` calls and `<CanClient>` components
 * anywhere in the subtree.
 *
 * Place this in your root Client Component (e.g. a client layout wrapper) so
 * the bitmask is decoded a single time per render tree.
 *
 * @example
 * ```tsx
 * // app/layout.tsx
 * export default async function RootLayout({ children }) {
 *   const session = await getSession()
 *   const { bitmask } = getPermissionMap(policy, session.role)
 *
 *   return (
 *     <html>
 *       <body>
 *         <PermissionBitmaskProvider bitmask={bitmask}>
 *           {children}
 *         </PermissionBitmaskProvider>
 *       </body>
 *     </html>
 *   )
 * }
 * ```
 */
export function PermissionBitmaskProvider({
  bitmask,
  children,
}: PermissionBitmaskProviderProps): ReactNode {
  const decoded = useMemo(() => fromBitmask(bitmask), [bitmask])
  return createElement(BitmaskCtx.Provider, { value: decoded }, children)
}

// ---------------------------------------------------------------------------
// usePermissions hook
// ---------------------------------------------------------------------------

/**
 * Returns a `PermissionBitmask` that performs permission checks locally in the
 * browser — no server round-trips, no engine import.
 *
 * **Two usage patterns:**
 *
 * 1. **With provider** — call with no arguments inside a `<PermissionBitmaskProvider>`:
 *    ```tsx
 *    const perms = usePermissions()
 *    ```
 *
 * 2. **Standalone** — pass the bitmask string directly (no provider needed):
 *    ```tsx
 *    const perms = usePermissions(bitmask)
 *    ```
 *
 * @param bitmask - Optional base64url string. When provided, overrides the context.
 * @returns A `PermissionBitmask` with `.can()`, `.cannot()`, `.canAll()`, `.canAny()`.
 *
 * @throws When called without a `bitmask` argument outside a `<PermissionBitmaskProvider>`.
 *
 * @example
 * ```tsx
 * const perms = usePermissions()
 * perms.can('posts:read')          // → boolean
 * perms.canAll(['posts:read', 'posts:write'])
 * perms.canAny(['admin:access', 'moderator:access'])
 * ```
 */
export function usePermissions(bitmask?: string): PermissionBitmask {
  const ctx = useContext(BitmaskCtx)

  // Inline bitmask — decode it (memoised by the hook caller's render).
  // eslint-disable-next-line react-hooks/rules-of-hooks
  const inlined = useMemo(
    () => (bitmask !== undefined ? fromBitmask(bitmask) : null),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [bitmask],
  )

  if (inlined !== null) return inlined

  if (ctx === null) {
    throw new Error(
      '[permzplus] usePermissions() must be called with a bitmask string or inside a <PermissionBitmaskProvider>.',
    )
  }
  return ctx
}

// ---------------------------------------------------------------------------
// useCan — single-permission shorthand
// ---------------------------------------------------------------------------

/**
 * Returns `true` when the current user has the given permission.
 * Reads from the nearest `<PermissionBitmaskProvider>` in the tree.
 *
 * @example
 * ```tsx
 * const canDelete = useCan('posts:delete')
 * return canDelete ? <DeleteButton /> : null
 * ```
 */
export function useCan(permission: string): boolean {
  return usePermissions().can(permission)
}

// ---------------------------------------------------------------------------
// CanClient — declarative client-side permission gate
// ---------------------------------------------------------------------------

export interface CanClientProps {
  /** The permission string to check (e.g. `"posts:delete"`). */
  permission: string
  /** Content to render when the check passes. */
  children: ReactNode
  /** Content to render when the check fails. Defaults to `null`. */
  fallback?: ReactNode
  /**
   * Optional bitmask string. When provided, bypasses the context and decodes
   * the bitmask inline. Useful when a provider is not available.
   */
  bitmask?: string
}

/**
 * Client-side permission gate component.
 *
 * Reads the decoded `PermissionBitmask` from the nearest
 * `<PermissionBitmaskProvider>` (or from the optional `bitmask` prop) and
 * renders `children` when the check passes, `fallback` otherwise.
 *
 * All checks run locally in the browser — no server round-trips.
 *
 * @example With provider
 * ```tsx
 * <CanClient permission="posts:delete" fallback={<span>Read-only</span>}>
 *   <DeleteButton />
 * </CanClient>
 * ```
 *
 * @example Without provider (inline bitmask)
 * ```tsx
 * <CanClient permission="posts:delete" bitmask={bitmask}>
 *   <DeleteButton />
 * </CanClient>
 * ```
 */
export function CanClient({
  permission,
  children,
  fallback = null,
  bitmask,
}: CanClientProps): ReactNode {
  const perms = usePermissions(bitmask)
  return (perms.can(permission) ? children : fallback) as ReactNode
}
