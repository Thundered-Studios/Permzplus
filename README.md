# permzplus

**Role-based and attribute-based permissions for TypeScript/JavaScript.**

RBAC with hierarchical inheritance for simple checks. ABAC with MongoDB-style subject conditions and database query generation for complex, data-aware authorization — all in one zero-dependency library.

```ts
// Simple RBAC check
policy.can('ADMIN', 'users:delete')

// ABAC — "can this user edit this specific post?"
policy.defineRule('MEMBER', 'posts:edit', (post, ctx) => post.authorId === ctx.userId)
policy.can('MEMBER', 'posts:edit', post, { userId: currentUser.id })

// Query builder — fetch only what the user can see
const { unrestricted, conditions } = accessibleBy(policy, 'MEMBER', 'posts:read')
const posts = await prisma.post.findMany({ where: unrestricted ? {} : { OR: conditions } })
```

---

## Features

- **RBAC** — hierarchical roles, wildcard permissions, explicit deny overrides
- **ABAC** — attach conditions to rules; evaluate against real data objects
- **Query builder** — `accessibleBy()` converts rules to Prisma/Mongoose/Drizzle WHERE clauses
- **Field-level permissions** — `permittedFieldsOf()` for per-field access control
- **Zero dependencies** — 2 KB core, tree-shakable
- **Framework adapters** — React, Vue, Angular, Express, Next.js, Fastify, Hono, NestJS
- **ORM adapters** — Prisma, Mongoose, Drizzle, Firebase, custom
- **Full-stack** — share one policy between TypeScript frontend and Python (FastAPI) backend
- **Serializable** — `toJSON()` / `fromJSON()` for sending policies over the wire

---

## Installation

```bash
npm install permzplus
# or
pnpm add permzplus
```

---

## Quick Start

### Define a policy

```ts
import { defineAbility } from 'permzplus'

const policy = defineAbility(({ role }) => {
  role('SUPER_ADMIN', 3, (can) => {
    can('*')
  })
  role('ORG_ADMIN', 2, (can, cannot) => {
    can('sites:*', 'templates:*', 'users:read')
    cannot('billing:delete')
  })
  role('MEMBER', 1, (can) => {
    can('content:read', 'content:create', 'posts:read', 'posts:edit')
  })
})

policy.can('ORG_ADMIN', 'sites:create')  // true — direct
policy.can('ORG_ADMIN', 'content:read')  // true — inherited from MEMBER
policy.can('MEMBER', 'billing:delete')   // false
policy.safeCan('', 'content:read')       // false — safe for unauthenticated users
```

---

## ABAC — Attribute-Based Conditions

Attach conditions to individual rules. When you pass a subject to `can()`, all conditions are evaluated against it.

### Object conditions (serializable)

Use MongoDB-style operators. These work with `can()` and with `accessibleBy()` for query building.

```ts
// Only published posts are readable by MEMBERs
policy.defineRule('MEMBER', 'posts:read', { status: 'published' })

// MEMBERs can only edit their own posts
policy.defineRule('MEMBER', 'posts:edit', { authorId: currentUser.id })

policy.can('MEMBER', 'posts:read', { status: 'published', authorId: 'u2' })  // true
policy.can('MEMBER', 'posts:read', { status: 'draft',     authorId: 'u2' })  // false
```

### Function conditions

For logic that can't be expressed as a plain object — receives the subject and a context object.

```ts
policy.defineRule('MEMBER', 'posts:edit',
  (post, ctx) => post.authorId === ctx?.userId && post.status !== 'locked'
)

policy.can('MEMBER', 'posts:edit', post, { userId: 'u1' })  // true/false
```

### Supported operators

`$eq` `$ne` `$gt` `$gte` `$lt` `$lte` `$in` `$nin` `$exists` `$regex` `$and` `$or` `$nor`

```ts
policy.defineRule('MODERATOR', 'posts:delete', {
  status: { $in: ['flagged', 'spam'] },
  reportCount: { $gte: 3 },
})

policy.defineRule('MEMBER', 'posts:read', {
  $or: [{ status: 'published' }, { authorId: currentUser.id }]
})
```

### Per-request context

Create a context once per request — the `userId` is automatically forwarded to all function conditions.

```ts
const ctx = policy.createContext('MEMBER', { userId: req.user.id })

ctx.can('posts:edit', post)          // condition receives { userId: req.user.id }
ctx.cannot('posts:delete', post)
ctx.assert('posts:edit', post)       // throws PermissionDeniedError if denied
```

---

## Query Builder

`accessibleBy()` converts your ABAC rules into database-ready WHERE conditions. No more manually writing `WHERE authorId = ?` — derive it from the policy.

```ts
import { accessibleBy } from 'permzplus/query'
```

### Prisma

```ts
const { permitted, unrestricted, conditions } = accessibleBy(policy, 'MEMBER', 'posts:read')

if (!permitted) return []  // no access at all

const posts = await prisma.post.findMany({
  where: unrestricted ? {} : { OR: conditions },
})
```

### Mongoose

```ts
const { permitted, unrestricted, conditions } = accessibleBy(policy, 'MEMBER', 'posts:read')

const filter = unrestricted ? {} : { $or: conditions }
const posts = await Post.find(filter)
```

### Multi-role merge

```ts
import { mergeAccessible } from 'permzplus/query'

const access = mergeAccessible(
  accessibleBy(policy, 'MEMBER', 'posts:read'),
  accessibleBy(policy, 'MODERATOR', 'posts:read'),
)
const posts = await prisma.post.findMany({ where: access.unrestricted ? {} : { OR: access.conditions } })
```

### `AccessibleByResult`

| Field | Type | Meaning |
|---|---|---|
| `permitted` | `boolean` | Role has this permission at all |
| `unrestricted` | `boolean` | Permitted with no conditions — return all records |
| `conditions` | `object[]` | MongoDB-style objects to apply as `OR` filter |

> **Note:** Only object-form conditions appear in `conditions`. Function conditions require subject-aware `can()` checks instead.

---

## Field-Level Permissions

Use `resource.field:action` permission format and `permittedFieldsOf()` to restrict access to specific fields.

```ts
policy.addRole({
  name: 'EDITOR',
  level: 2,
  permissions: ['post.title:edit', 'post.body:edit', 'post.status:read'],
})

policy.permittedFieldsOf('EDITOR', 'post', 'edit')  // → ['title', 'body']
policy.permittedFieldsOf('EDITOR', 'post', 'read')  // → ['status']
```

---

## React

```tsx
import { PermissionProvider, usePermission, useAbility, Can } from 'permzplus/react'

function App() {
  return (
    <PermissionProvider engine={policy} role={user.role ?? ''}>
      <Dashboard />
    </PermissionProvider>
  )
}

// Hook
function EditButton({ post }) {
  const ability = useAbility()
  if (!ability.can('posts:edit', () => post.authorId === userId)) return null
  return <button>Edit</button>
}

// Declarative
function Toolbar() {
  return (
    <Can permission="posts:delete" fallback={<span>Read-only</span>}>
      <DeleteButton />
    </Can>
  )
}

// CASL-style I/a props
function EditForm() {
  return <Can I="edit" a="post"><PostEditor /></Can>
}
```

---

## Vue

```ts
import { providePermissions, usePermission } from 'permzplus/vue'

// Root component
providePermissions(policy, user.role)

// In child component
const canDelete = usePermission('posts:delete')  // ComputedRef<boolean>
```

---

## Angular

```ts
import { PermissionService, CanDirective, HasPermissionPipe, PermzModule } from 'permzplus-angular'

// Set up (e.g. AppComponent.ngOnInit)
constructor(private perms: PermissionService) {
  perms.setEngine(policy)
  perms.setRole(currentUser.role)
}

// Reactive signal
canEdit = this.perms.canSignal('posts:edit')
```

```html
<!-- Directive -->
<button *permzCan="'posts:delete'">Delete</button>
<div *permzCan="'posts:edit'; else readOnly">...</div>

<!-- Pipe -->
<button [disabled]="!('posts:edit' | hasPermission)">Edit</button>
```

---

## Express / Fastify / Hono / NestJS

```ts
// Express
import { expressGuard } from 'permzplus/guard'
app.delete('/posts/:id', expressGuard(policy, 'posts:delete'), handler)

// Fastify
import { FastifyPermzPlugin } from 'permzplus/adapters/fastify'
fastify.register(FastifyPermzPlugin, { policy })

// Hono
import { honoPermzMiddleware } from 'permzplus/adapters/hono'
app.use('/admin/*', honoPermzMiddleware(policy, 'admin:panel'))

// NestJS
import { PermzGuard, RequirePermission } from 'permzplus/adapters/nest'
@UseGuards(PermzGuard)
@RequirePermission('posts:delete')
async deletePost() { ... }
```

---

## Database Adapters

### Prisma

```ts
import { PrismaAdapter } from 'permzplus/adapters/prisma'
const policy = await PolicyEngine.fromAdapter(new PrismaAdapter(prisma))
```

### Mongoose

```ts
import { MongooseAdapter } from 'permzplus/adapters/mongoose'
const policy = await PolicyEngine.fromAdapter(new MongooseAdapter(mongoose))
```

### Drizzle

```ts
import { DrizzleAdapter } from 'permzplus/adapters/drizzle'
const policy = await PolicyEngine.fromAdapter(new DrizzleAdapter(db, tables))
```

### Firebase / Firestore

```ts
import { FirebaseAdapter } from 'permzplus/adapters/firebase'
const policy = await PolicyEngine.fromAdapter(new FirebaseAdapter(db))
```

---

## Full-Stack — Share Policy with Python (FastAPI)

permzplus is the only permissions library with a FastAPI adapter. Define your policy once, enforce it on both the React frontend and Python backend.

```ts
// Frontend — TypeScript
import { defineAbility } from 'permzplus'
export const policy = defineAbility(({ role }) => {
  role('MEMBER', 1, (can) => can('posts:read', 'posts:edit'))
  role('ADMIN', 2, (can) => can('*'))
})
```

```python
# Backend — Python / FastAPI
from permzplus_fastapi import PolicyEngine, require_permission

policy = PolicyEngine(roles=[
  {"name": "MEMBER", "level": 1, "permissions": ["posts:read", "posts:edit"]},
  {"name": "ADMIN",  "level": 2, "permissions": ["*"]},
])

@app.get("/posts")
async def get_posts(user = Depends(require_permission(policy, "posts:read"))):
    ...
```

---

## Serialization

Send the policy over the wire — serialize on the server, reconstruct on the client.

```ts
// Server
const snapshot = policy.toJSON()
res.json(snapshot)

// Client
const policy = PolicyEngine.fromJSON(snapshot)
```

---

## Audit Logging

```ts
import { InMemoryAuditLogger } from 'permzplus'

const audit = new InMemoryAuditLogger()
const policy = new PolicyEngine({ audit })

policy.grantTo('MEMBER', 'posts:create')

audit.events
// [{ action: 'permission.grant', role: 'MEMBER', permission: 'posts:create', timestamp: ... }]
```

---

## Spread the Word

If permzplus saves you time, help others find it:

- **Star the repo** on [GitHub](https://github.com/PermzPlus/Permzplus) — it helps with discoverability
- **Share it** with your team, in Discord servers, or on Twitter/X
- **Write about it** — blog posts, dev.to articles, or Stack Overflow answers go a long way
- **Open issues or PRs** — feedback and contributions make the library better for everyone

The project is solo-maintained. Every star, share, and mention genuinely helps.

---

## License

MIT
