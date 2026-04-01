import type { IPolicyEngine } from '../types'
import { PermissionDeniedError, UnknownRoleError } from '../errors'

/**
 * Creates a NestJS `CanActivate` guard class that enforces a single permission.
 *
 * Returns a class (not an instance) so it can be used with `@UseGuards()` or
 * `app.useGlobalGuards()`. Extracts the role from the request using
 * `getRoleFromReq` (if provided) or falls back to `request.user?.role`.
 *
 * Throws `PermissionDeniedError` on 403 and a generic `Error` on 401 — these
 * map to NestJS exception filters. Wire up a filter for `PermissionDeniedError`
 * if you want a custom 403 response shape.
 *
 * @example
 * ```ts
 * import { Controller, Get, UseGuards } from '@nestjs/common'
 * import { PolicyEngine } from 'permzplus'
 * import { createNestGuard } from 'permzplus/adapters/nest'
 *
 * const policy = new PolicyEngine({ roles: [...] })
 * const CanReadPosts = createNestGuard(policy, 'posts:read')
 *
 * @Controller('posts')
 * export class PostsController {
 *   @Get()
 *   @UseGuards(CanReadPosts)
 *   findAll() { ... }
 * }
 * ```
 */
export function createNestGuard(
  engine: IPolicyEngine,
  permission: string,
  getRoleFromReq?: (request: unknown) => string | undefined,
): new () => { canActivate(context: unknown): boolean } {
  return class PermzNestGuard {
    canActivate(context: unknown): boolean {
      const http = (context as any).switchToHttp()
      const request = http.getRequest()

      const role = getRoleFromReq ? getRoleFromReq(request) : request?.user?.role

      if (!role) {
        // Throwing a plain Error here; consumers can map it to UnauthorizedException
        // in their exception filter or use the getRoleFromReq hook to throw directly.
        throw new Error('Unauthorized: no role found on request')
      }

      try {
        engine.assert(role, permission)
        return true
      } catch (err) {
        if (err instanceof PermissionDeniedError || err instanceof UnknownRoleError) {
          throw err
        }
        throw err
      }
    }
  }
}

/**
 * Creates a NestJS guard that enforces ALL of the given permissions.
 *
 * @example
 * ```ts
 * const CanManagePosts = createNestGuardAll(policy, ['posts:read', 'posts:write'])
 * ```
 */
export function createNestGuardAll(
  engine: IPolicyEngine,
  permissions: string[],
  getRoleFromReq?: (request: unknown) => string | undefined,
): new () => { canActivate(context: unknown): boolean } {
  return class PermzNestGuardAll {
    canActivate(context: unknown): boolean {
      const http = (context as any).switchToHttp()
      const request = http.getRequest()

      const role = getRoleFromReq ? getRoleFromReq(request) : request?.user?.role

      if (!role) {
        throw new Error('Unauthorized: no role found on request')
      }

      engine.assertAll(role, permissions)
      return true
    }
  }
}

/**
 * Creates a NestJS guard that enforces AT LEAST ONE of the given permissions.
 *
 * @example
 * ```ts
 * const CanViewAdmin = createNestGuardAny(policy, ['admin:read', 'admin:write'])
 * ```
 */
export function createNestGuardAny(
  engine: IPolicyEngine,
  permissions: string[],
  getRoleFromReq?: (request: unknown) => string | undefined,
): new () => { canActivate(context: unknown): boolean } {
  return class PermzNestGuardAny {
    canActivate(context: unknown): boolean {
      const http = (context as any).switchToHttp()
      const request = http.getRequest()

      const role = getRoleFromReq ? getRoleFromReq(request) : request?.user?.role

      if (!role) {
        throw new Error('Unauthorized: no role found on request')
      }

      engine.assertAny(role, permissions)
      return true
    }
  }
}
