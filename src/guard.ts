export function createGuard(policy: unknown) {
  return function (_opts: { role: string; permission: string }): void {
    throw new Error('Not implemented')
  }
}

export function expressGuard(_req: unknown, _res: unknown, _next: unknown): void {
  throw new Error('Not implemented')
}
