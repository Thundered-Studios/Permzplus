import type { RoleDefinition } from './types'

export const BUILT_IN_ROLES: RoleDefinition[] = [
  {
    name: 'GUEST',
    level: 0,
    permissions: ['posts:read'],
  },
  {
    name: 'USER',
    level: 20,
    permissions: ['posts:read', 'posts:write', 'comments:read', 'comments:write'],
  },
  {
    name: 'MODERATOR',
    level: 40,
    permissions: ['posts:delete', 'comments:delete', 'users:warn'],
  },
  {
    name: 'DEVELOPER',
    level: 60,
    permissions: ['admin:debug', 'admin:logs'],
  },
  {
    name: 'ADMIN',
    level: 80,
    permissions: ['users:ban', 'users:delete', 'admin:panel'],
  },
  {
    name: 'SUPER_ADMIN',
    level: 100,
    permissions: ['*'],
  },
]

export const BUILT_IN_ROLE_NAMES = ['GUEST', 'USER', 'MODERATOR', 'DEVELOPER', 'ADMIN', 'SUPER_ADMIN'] as const

export type BuiltInRole = typeof BUILT_IN_ROLE_NAMES[number]
