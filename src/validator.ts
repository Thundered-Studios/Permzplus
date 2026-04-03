import type { RoleDefinition } from './types'
import { validatePermission } from './permissions'

export interface ValidationIssue {
  type: 'orphaned_group' | 'invalid_level' | 'duplicate_level' | 'invalid_permission' | 'undefined_group_ref'
  role: string
  detail: string
}

export interface ValidationResult {
  valid: boolean
  issues: ValidationIssue[]
}

/**
 * Validates a set of role definitions for common structural problems:
 *
 * - **invalid_level** — a role's level is not a non-negative integer
 * - **duplicate_level** — two roles share the same numeric level
 * - **orphaned_group** — a role references a group name not present in `groups`
 * - **invalid_permission** — a permission string fails the format check
 *
 * This is a pure function and a separate export so it tree-shakes out of
 * production bundles that don't need validation at runtime.
 *
 * @example
 * import { validate } from 'permzplus/validator'
 * const { valid, issues } = validate(roles, groups)
 */
export function validate(
  roles: RoleDefinition[],
  groups?: Record<string, string[]>,
): ValidationResult {
  const issues: ValidationIssue[] = []
  const knownGroups = new Set(Object.keys(groups ?? {}))
  const seenLevels = new Map<number, string>()

  for (const role of roles) {
    if (!Number.isInteger(role.level) || role.level < 0) {
      issues.push({ type: 'invalid_level', role: role.name, detail: `Role "${role.name}" has an invalid level: ${role.level}` })
    } else if (seenLevels.has(role.level)) {
      issues.push({ type: 'duplicate_level', role: role.name, detail: `Role "${role.name}" and "${seenLevels.get(role.level)}" both use level ${role.level}` })
    } else {
      seenLevels.set(role.level, role.name)
    }

    for (const perm of role.permissions) {
      if (!validatePermission(perm)) {
        issues.push({ type: 'invalid_permission', role: role.name, detail: `Role "${role.name}" has an invalid permission: "${perm}"` })
      }
    }

    for (const group of role.groups ?? []) {
      if (!knownGroups.has(group)) {
        issues.push({ type: 'orphaned_group', role: role.name, detail: `Role "${role.name}" references unknown group "${group}"` })
      }
    }
  }

  for (const [groupName, members] of Object.entries(groups ?? {})) {
    for (const member of members) {
      if (member.startsWith('@')) {
        const refName = member.slice(1)
        if (!knownGroups.has(refName)) {
          issues.push({ type: 'undefined_group_ref', role: groupName, detail: `Group "${groupName}" references undefined group "@${refName}"` })
        }
      }
    }
  }

  return { valid: issues.length === 0, issues }
}
