export class PermissionDeniedError extends Error {
  constructor(role: string, permission: string) {
    super(`Role "${role}" does not have permission "${permission}"`)
    this.name = 'PermissionDeniedError'
  }
}

export class UnknownRoleError extends Error {
  constructor(role: string) {
    super(`Unknown role: "${role}"`)
    this.name = 'UnknownRoleError'
  }
}

export class InvalidPermissionError extends Error {
  constructor(permission: string) {
    super(`Invalid permission string: "${permission}"`)
    this.name = 'InvalidPermissionError'
  }
}

export class AdapterError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'AdapterError'
  }
}

export class BuiltInRoleError extends Error {
  constructor(role: string) {
    super(`Role "${role}" is a built-in role and cannot be removed`)
    this.name = 'BuiltInRoleError'
  }
}
