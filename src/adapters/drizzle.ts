import type { PermzAdapter } from '../types'

export class DrizzleAdapter implements PermzAdapter {
  constructor(private drizzle: unknown) {}
  getRoles() { return Promise.resolve([]) }
  getPermissions(_role: string) { return Promise.resolve([]) }
  saveRole() { return Promise.resolve() }
  deleteRole() { return Promise.resolve() }
  grantPermission() { return Promise.resolve() }
  revokePermission() { return Promise.resolve() }
}
