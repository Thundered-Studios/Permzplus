/**
 * Permzplus Custom Adapter Example
 *
 * This script demonstrates how to implement the PermzAdapter interface and
 * wire it into PolicyEngine.fromAdapter(). The adapter shown here stores
 * everything in a plain JavaScript object (no real I/O), making it easy to
 * follow the shape of the interface without database boilerplate.
 *
 * In a real application you would replace the in-memory `this.data` reads and
 * writes with database calls — e.g. `await db.role.findMany()` for a Prisma
 * adapter, or `fs.readFile` / `fs.writeFile` for a JSON-file adapter.
 */

import { PolicyEngine } from 'permzplus'

// ── Custom adapter implementation ─────────────────────────────────────────────
//
// The PermzAdapter interface requires exactly six async methods:
//
//   getRoles()                          → Promise<RoleDefinition[]>
//   getPermissions(role)                → Promise<string[]>
//   saveRole(role)                      → Promise<void>
//   deleteRole(role)                    → Promise<void>
//   grantPermission(role, permission)   → Promise<void>
//   revokePermission(role, permission)  → Promise<void>
//
// A RoleDefinition is: { name: string, level: number, permissions: string[] }
//
// PolicyEngine.fromAdapter() will:
//   1. Call getRoles() to see what is already stored.
//   2. Seed any built-in roles that are missing by calling saveRole + grantPermission.
//   3. Call getRoles() again, then getPermissions(role) for each role.
//   4. Return a fully initialised PolicyEngine with those roles loaded.

class JsonFileAdapter {
  constructor() {
    // In a real JSON-file adapter this object would be loaded from disk in an
    // async `init()` method and flushed back to disk after every mutation.
    // Here it is simply an in-memory store so the example runs without any I/O.
    this.data = {
      roles: {},       // { [roleName]: { name, level } }
      permissions: {}, // { [roleName]: string[] }
    }
  }

  // Returns every stored role as an array of RoleDefinition objects.
  // getRoles is called by fromAdapter() on startup to discover existing data.
  async getRoles() {
    return Object.values(this.data.roles).map((role) => ({
      ...role,
      // Attach the stored permission list so callers have a complete picture.
      permissions: this.data.permissions[role.name] ?? [],
    }))
  }

  // Returns the permission strings stored for a given role.
  // fromAdapter() calls this for every role returned by getRoles().
  async getPermissions(role) {
    return [...(this.data.permissions[role] ?? [])]
  }

  // Persists a role's metadata (name + level). Permission strings are stored
  // separately via grantPermission so they can be managed independently.
  async saveRole(role) {
    this.data.roles[role.name] = { name: role.name, level: role.level }
    // Initialise the permission list if this is a brand-new role.
    if (!this.data.permissions[role.name]) {
      this.data.permissions[role.name] = []
    }
    console.log(`  [adapter] saveRole("${role.name}", level=${role.level})`)
  }

  // Removes a role and all its associated permissions from the store.
  async deleteRole(role) {
    delete this.data.roles[role]
    delete this.data.permissions[role]
    console.log(`  [adapter] deleteRole("${role}")`)
  }

  // Adds a single permission to a role's list (deduplicates automatically).
  async grantPermission(role, permission) {
    if (!this.data.permissions[role]) {
      this.data.permissions[role] = []
    }
    if (!this.data.permissions[role].includes(permission)) {
      this.data.permissions[role].push(permission)
    }
    console.log(`  [adapter] grantPermission("${role}", "${permission}")`)
  }

  // Removes a single permission from a role's list.
  async revokePermission(role, permission) {
    if (this.data.permissions[role]) {
      this.data.permissions[role] = this.data.permissions[role].filter((p) => p !== permission)
    }
    console.log(`  [adapter] revokePermission("${role}", "${permission}")`)
  }
}

// ── Bootstrap ─────────────────────────────────────────────────────────────────

console.log('=== Permzplus Custom Adapter Example ===')
console.log()
console.log('Initialising PolicyEngine from adapter...')
console.log('(Adapter log lines are prefixed with [adapter])')
console.log()

// PolicyEngine.fromAdapter() is async. It seeds built-in roles into the adapter
// automatically, so the adapter log will show saveRole/grantPermission calls for
// every built-in role that is not yet in the store.
const policy = await PolicyEngine.fromAdapter(new JsonFileAdapter())

console.log()
console.log('Engine ready. Running permission checks...')
console.log()

// ── Wildcard check ────────────────────────────────────────────────────────────
//
// SUPER_ADMIN has the "*" permission, which matches any permission string.
// can() returns true for any non-empty, colon-delimited permission identifier.

const superAdminCanAnything = policy.can('SUPER_ADMIN', 'anything:ever')
console.log(`SUPER_ADMIN can anything:ever:       ${superAdminCanAnything}`)  // true

// ── Inherited permission check ────────────────────────────────────────────────
//
// USER is level 20. Levels are hierarchical — a role inherits all permissions
// from every role whose level is <= its own. GUEST (level 0) has posts:read,
// so USER inherits it.

const userCanRead = policy.can('USER', 'posts:read')
console.log(`USER can posts:read:                 ${userCanRead}`)  // true

// USER does not have posts:delete (that belongs to MODERATOR, level 40).
const userCanDelete = policy.can('USER', 'posts:delete')
console.log(`USER can posts:delete:               ${userCanDelete}`)  // false

// ── Adding a custom role ──────────────────────────────────────────────────────
//
// addRole() registers the role in the engine and also calls adapter.saveRole()
// and adapter.grantPermission() for each permission (fire-and-forget).

console.log()
console.log('Adding custom ANALYST role (level 25)...')
policy.addRole({ name: 'ANALYST', level: 25, permissions: ['reports:read', 'reports:export'] })

const analystCanExport = policy.can('ANALYST', 'reports:export')
console.log(`ANALYST can reports:export:          ${analystCanExport}`)  // true

// ANALYST is level 25, which is above USER (20) and GUEST (0), so it inherits
// their permissions too.
const analystCanReadPosts = policy.can('ANALYST', 'posts:read')
console.log(`ANALYST can posts:read (inherited):  ${analystCanReadPosts}`)  // true

// ── grantTo — adding a permission to an existing role ─────────────────────────
//
// grantTo() pushes a new permission into the role's list and calls
// adapter.grantPermission() in the background.

console.log()
console.log('Granting reports:share to ANALYST...')
policy.grantTo('ANALYST', 'reports:share')

const analystCanShare = policy.can('ANALYST', 'reports:share')
console.log(`ANALYST can reports:share:           ${analystCanShare}`)  // true

// ── denyFrom — explicit override that beats inheritance ───────────────────────
//
// denyFrom() adds the permission to the role's deny list. The deny list is
// evaluated AFTER the inherited permission set, so it always wins.
// Crucially, the deny is NOT inherited by higher-level roles — only this
// specific role is affected.

console.log()
console.log('Denying posts:read from ANALYST...')
policy.denyFrom('ANALYST', 'posts:read')

const analystCanReadPostsAfterDeny = policy.can('ANALYST', 'posts:read')
console.log(`ANALYST can posts:read (after deny): ${analystCanReadPostsAfterDeny}`)  // false

// Higher-level roles are unaffected by another role's deny list.
const adminCanReadPosts = policy.can('ADMIN', 'posts:read')
console.log(`ADMIN can posts:read (unaffected):   ${adminCanReadPosts}`)  // true

// ── isAtLeast — level comparison utility ─────────────────────────────────────
//
// Useful for gating UI features based on a minimum role tier without
// specifying an exact permission string.

console.log()
const analystIsAtLeastUser = policy.isAtLeast('ANALYST', 'USER')
console.log(`ANALYST isAtLeast USER:              ${analystIsAtLeastUser}`)  // true (25 >= 20)

const guestIsAtLeastModerator = policy.isAtLeast('GUEST', 'MODERATOR')
console.log(`GUEST isAtLeast MODERATOR:           ${guestIsAtLeastModerator}`)  // false (0 < 40)

console.log()
console.log('Done.')
