import type { PolicyOptions, RoleDefinition, PermzAdapter } from './types'
import { BUILT_IN_ROLES } from './roles'
import { PermissionDeniedError, UnknownRoleError } from './errors'
import { PermissionContext } from './context'

export class PolicyEngine {
  constructor(_options?: PolicyOptions) {}

  can(_role: string, _permission: string): boolean {
    throw new Error('Not implemented')
  }

  cannot(_role: string, _permission: string): boolean {
    throw new Error('Not implemented')
  }

  assert(_role: string, _permission: string): void {
    throw new Error('Not implemented')
  }

  getRoleLevel(_role: string): number {
    throw new Error('Not implemented')
  }

  isAtLeast(_role: string, _minRole: string): boolean {
    throw new Error('Not implemented')
  }

  createContext(_role: string): PermissionContext {
    throw new Error('Not implemented')
  }

  addRole(_role: RoleDefinition): void {
    throw new Error('Not implemented')
  }

  grantTo(_role: string, _permission: string): void {
    throw new Error('Not implemented')
  }

  denyFrom(_role: string, _permission: string): void {
    throw new Error('Not implemented')
  }

  static async fromAdapter(_adapter: PermzAdapter): Promise<PolicyEngine> {
    throw new Error('Not implemented')
  }
}
