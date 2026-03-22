export class PermissionContext {
  constructor(private role: string, private policy: unknown) {}

  can(_permission: string): boolean {
    throw new Error('Not implemented')
  }

  cannot(_permission: string): boolean {
    throw new Error('Not implemented')
  }

  assert(_permission: string): void {
    throw new Error('Not implemented')
  }

  isAtLeast(_minRole: string): boolean {
    throw new Error('Not implemented')
  }
}
