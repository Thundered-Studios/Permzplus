import type { PermzAdapter } from '../types'

export class MongooseAdapter implements PermzAdapter {
  constructor(private mongoose: unknown) {}
  getRoles() { return Promise.resolve([]) }
  getPermissions(_role: string) { return Promise.resolve([]) }
  saveRole() { return Promise.resolve() }
  deleteRole() { return Promise.resolve() }
  grantPermission() { return Promise.resolve() }
  revokePermission() { return Promise.resolve() }
}
