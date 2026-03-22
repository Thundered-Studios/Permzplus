import { IPolicyEngine } from './types'
import { PermissionDeniedError } from './errors'

/**
 * Creates a simple guard function bound to the given policy engine.
 * The returned function accepts `{ role, permission }` and returns `true`
 * if the role has the permission, `false` otherwise.
 *
 * @param engine - Any object implementing `IPolicyEngine`.
 * @returns A predicate `(opts: { role: string; permission: string }) => boolean`.
 */
export function createGuard(
  engine: IPolicyEngine
): (opts: { role: string; permission: string }) => boolean {
  return function ({ role, permission }: { role: string; permission: string }): boolean {
    return engine.can(role, permission)
  }
}

/**
 * Creates an Express-style middleware that enforces a single permission.
 * Extracts the role from the request using `getRoleFromReq` (if provided) or
 * falls back to `(req as any).user?.role`.
 *
 * - Responds with `401 Unauthorized` if no role can be determined.
 * - Responds with `403 Forbidden` if the role lacks the required permission.
 * - Forwards any unexpected errors to the next error handler.
 *
 * @param engine - Any object implementing `IPolicyEngine`.
 * @param permission - The permission string to enforce on every request.
 * @param getRoleFromReq - Optional function to extract a role string from the request object.
 * @returns An Express middleware `(req, res, next) => void`.
 */
export function expressGuard(
  engine: IPolicyEngine,
  permission: string,
  getRoleFromReq?: (req: unknown) => string | undefined
): (req: unknown, res: unknown, next: unknown) => void {
  return function (req: unknown, res: unknown, next: unknown): void {
    const role = getRoleFromReq
      ? getRoleFromReq(req)
      : (req as any)?.user?.role

    if (!role) {
      ;(res as any).status(401).json({ error: 'Unauthorized' })
      return
    }

    try {
      engine.assert(role, permission)
      ;(next as any)()
    } catch (err) {
      if (err instanceof PermissionDeniedError) {
        ;(res as any).status(403).json({ error: 'Forbidden' })
        return
      }
      ;(next as any)(err)
    }
  }
}
