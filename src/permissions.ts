const PERMISSION_PATTERN = /^(\*|[a-zA-Z0-9_-]+:\*|[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+)$/

export function validatePermission(permission: string): boolean {
  return PERMISSION_PATTERN.test(permission)
}

export function matchesPermission(permission: string, pattern: string): boolean {
  if (pattern === '*') return true
  if (permission === pattern) return true
  const [patternResource, patternAction] = pattern.split(':')
  const [permResource] = permission.split(':')
  if (patternAction === '*' && patternResource === permResource) return true
  return false
}
