# permzplus

Hierarchical role-based permissions library for TypeScript/JavaScript web applications.

- Zero runtime dependencies
- ESM + CJS + type declarations
- Chainable, fluent API
- Framework-agnostic core with optional Express/Next.js adapters
- Wildcard permissions, explicit deny overrides, per-request scoping

---

## Installation

```bash
npm install permzplus
# or
pnpm add permzplus
```

---

## Quick Start

```ts
import { PolicyEngine } from 'permzplus';

const policy = new PolicyEngine({
  roles: ['GUEST', 'USER', 'MODERATOR', 'ADMIN', 'SUPER_ADMIN'],
  permissions: {
    GUEST:       ['posts:read'],
    USER:        ['posts:write', 'comments:write'],
    MODERATOR:   ['posts:delete', 'comments:delete', 'users:warn'],
    ADMIN:       ['users:ban', 'users:delete', 'admin:panel'],
    SUPER_ADMIN: ['*'],
  },
});

policy.can('MODERATOR', 'posts:read');  // true — inherited from USER/GUEST
policy.can('USER', 'users:ban');        // false
policy.can('SUPER_ADMIN', 'anything'); // true — wildcard
```

---

## Role Hierarchy

Roles are ordered by privilege level. Each role automatically inherits all permissions from every role below it.

| Role        | Level |
|-------------|-------|
| SUPER_ADMIN | 100   |
| ADMIN       | 80    |
| DEVELOPER   | 60    |
| MODERATOR   | 40    |
| USER        | 20    |
| GUEST       | 0     |

Custom roles can be inserted at any level via `addRole()`.

---

## Permissions Format

Permissions use a `resource:action` string format:

```
posts:read
posts:write
users:ban
admin:panel
*              wildcard — matches everything
posts:*        resource wildcard — matches all actions on "posts"
```

---

## API Reference

### `PolicyEngine`

```ts
const policy = new PolicyEngine({ roles, permissions });
```

| Method | Signature | Description |
|--------|-----------|-------------|
| `can` | `(role, permission) => boolean` | Check if role has permission |
| `cannot` | `(role, permission) => boolean` | Inverse of `can` |
| `assert` | `(role, permission) => void` | Throws `PermissionDeniedError` if not allowed |
| `getRoleLevel` | `(role) => number` | Returns the numeric level of a role |
| `isAtLeast` | `(role, minRole) => boolean` | True if role level >= minRole level |
| `createContext` | `(opts) => PermissionContext` | Creates a scoped per-request context |
| `addRole` | `(role, level, permissions) => this` | Dynamically register a new role |
| `grantTo` | `(role, permission) => this` | Add a permission to an existing role |
| `denyFrom` | `(role, permission) => this` | Explicitly deny a permission (overrides inheritance) |

### `PermissionContext`

Bind a role once per request and check permissions without re-passing the role:

```ts
const ctx = policy.createContext({ role: 'MODERATOR', userId: '123' });

ctx.can('posts:delete');  // true
ctx.cannot('users:ban');  // true
ctx.assert('users:ban');  // throws PermissionDeniedError
ctx.isAtLeast('USER');    // true
```

| Method | Signature | Description |
|--------|-----------|-------------|
| `can` | `(permission) => boolean` | Check with bound role |
| `cannot` | `(permission) => boolean` | Inverse of `can` |
| `assert` | `(permission) => void` | Throws if not allowed |
| `isAtLeast` | `(minRole) => boolean` | Role level comparison |

---

## Dynamic Policy Mutation

All mutation methods are chainable:

```ts
policy
  .addRole('TESTER', 50, ['tests:run', 'tests:read'])
  .grantTo('TESTER', 'reports:view')
  .denyFrom('DEVELOPER', 'admin:panel');
```

---

## Deny Override

`denyFrom` explicitly blocks a permission even if it would be inherited:

```ts
// Everyone below ADMIN inherits billing:view — except DEVELOPER
policy.denyFrom('DEVELOPER', 'billing:view');

policy.can('ADMIN', 'billing:view');     // true
policy.can('DEVELOPER', 'billing:view'); // false — explicitly denied
policy.can('MODERATOR', 'billing:view'); // true — not denied
```

---

## Express Middleware

```ts
import { expressGuard } from 'permzplus/guard';

// Reads role from req.user.role by default
app.delete('/posts/:id', expressGuard(policy, 'posts:delete'), handler);
```

---

## Generic Guard

Works with any framework:

```ts
import { createGuard } from 'permzplus/guard';

const guard = createGuard(policy);
guard({ role: 'USER', permission: 'posts:delete' }); // throws or returns false
```

---

## Error Classes

Import from `permzplus/errors`:

```ts
import { PermissionDeniedError, UnknownRoleError, InvalidPermissionError } from 'permzplus/errors';
```

| Class | When thrown |
|-------|-------------|
| `PermissionDeniedError` | `assert()` called and permission is denied |
| `UnknownRoleError` | A role string is not registered in the policy |
| `InvalidPermissionError` | A permission string is malformed |

---

## Next.js Middleware

```ts
// middleware.ts
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'
import { PolicyEngine } from 'permzplus'
import { nextjsGuard } from 'permzplus/guard'

const policy = new PolicyEngine()

const adminGuard = nextjsGuard(policy, 'admin:panel', (req) => {
  return req.cookies.get('role')?.value
})

export function middleware(req: NextRequest) {
  if (req.nextUrl.pathname.startsWith('/admin')) {
    const blocked = adminGuard(req)
    if (blocked) return blocked
  }
  return NextResponse.next()
}
```

---

## Database Integration

Permzplus can persist roles and permissions to any database via adapters.

### Prisma

Add the required models to your schema (see `examples/prisma-adapter/schema.prisma`), then:

```ts
import { PrismaClient } from '@prisma/client'
import { PolicyEngine } from 'permzplus'
import { PrismaAdapter } from 'permzplus/adapters/prisma'

const prisma = new PrismaClient()
const policy = await PolicyEngine.fromAdapter(new PrismaAdapter(prisma))
```

Built-in roles are seeded to the database automatically on first run.

### Mongoose

```ts
import mongoose from 'mongoose'
import { PolicyEngine } from 'permzplus'
import { MongooseAdapter } from 'permzplus/adapters/mongoose'

await mongoose.connect(process.env.MONGO_URI)
const policy = await PolicyEngine.fromAdapter(new MongooseAdapter(mongoose))
```

### Drizzle

```ts
import { drizzle } from 'drizzle-orm/node-postgres'
import { PolicyEngine } from 'permzplus'
import { DrizzleAdapter } from 'permzplus/adapters/drizzle'

const db = drizzle(connectionString)
const tables = { roles: permzRoles, permissions: permzPermissions }
const policy = await PolicyEngine.fromAdapter(new DrizzleAdapter(db, tables))
```

### Custom Adapter

Implement the `PermzAdapter` interface:

```ts
import type { PermzAdapter, RoleDefinition } from 'permzplus'

class MyAdapter implements PermzAdapter {
  async getRoles(): Promise<RoleDefinition[]> { ... }
  async getPermissions(role: string): Promise<string[]> { ... }
  async saveRole(role: RoleDefinition): Promise<void> { ... }
  async deleteRole(role: string): Promise<void> { ... }
  async grantPermission(role: string, permission: string): Promise<void> { ... }
  async revokePermission(role: string, permission: string): Promise<void> { ... }
}
```

---

## License

MIT
