# permzplus

[![npm version](https://img.shields.io/npm/v/permzplus)](https://www.npmjs.com/package/permzplus)
[![Socket Badge](https://badge.socket.dev/npm/package/permzplus)](https://socket.dev/npm/package/permzplus)
[![Weekly Downloads](https://img.shields.io/npm/dw/permzplus)](https://www.npmjs.com/package/permzplus)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**RBAC + ABAC authorization for TypeScript — 2 KB, zero dependencies, edge-ready.**

CASL-style DX. 1/10th the footprint. Trusted by 230+ developers.

---

## The Builder (v3.2.0)

```ts
// Define                                   // Produces →
import { createPermz, PolicyEngine } from 'permzplus'

const snapshot = createPermz({ name: 'EDITOR', level: 20 })
  .can('read',   'posts')
  .can('write',  'posts')
  .cannot('delete', 'posts')
  .build()
```

```json
{
  "roles": [{ "name": "EDITOR", "level": 20, "permissions": ["posts:read", "posts:write"] }],
  "denies": { "EDITOR": ["posts:delete"] },
  "groups": {}
}
```

```ts
const policy = PolicyEngine.fromJSON(snapshot)
policy.can('EDITOR', 'posts:read')    // true
policy.can('EDITOR', 'posts:delete')  // false
```

Full TypeScript generics — lock down valid actions and resources at compile time:

```ts
type Action   = 'read' | 'write' | 'delete'
type Resource = 'posts' | 'comments'

createPermz<Action, Resource>({ name: 'MOD', level: 30 })
  .can('purge', 'posts')  // ✗ TS error — 'purge' not assignable to Action
```

---

## Why permzplus

| | **permzplus** | **CASL** | **Casbin** |
|---|---|---|---|
| **Bundle size** | 2 KB | 15 KB+ | 40 KB+ |
| **Dependencies** | 0 | 3+ | 10+ |
| **Resolver** | O(1) memoized | Recursive graph walk | Regex policy scan |
| **Security score** | 100/100 Socket | — | — |
| **Edge runtime** | Cloudflare Workers / Lambda@Edge | Partial | No |
| **Python sync** | FastAPI adapter | No | Separate SDK |
| **ABAC query gen** | Prisma / Mongoose / Drizzle / more | Mongo only | No |

---

## Performance

The hot path uses a three-layer resolver:

1. **`checkCache`** — flat-string Map lookup for repeated subject-free calls (O(1))
2. **Bitwise layer** — bitmask check for `read / write / delete / create` without iterating the permission Set (O(1))
3. **Set iteration** — fallback for custom actions or ABAC subject conditions

All three caches are invalidated atomically on any mutation.

### vs. CASL and accesscontrol

Benchmarked with [mitata](https://github.com/nicolo-ribaudo/mitata) on Node 22.16.0, Intel Core i7-1355U. Policy: 3 roles (VIEWER → EDITOR → ADMIN), hierarchical inheritance. Steady-state (cache warm).

| Scenario | permzplus | CASL | accesscontrol |
|---|---|---|---|
| VIEWER read Post (allowed) | **10.6 ns** | 12.2 ns | 447 ns |
| EDITOR write Post (allowed) | **8.4 ns** | 14.4 ns | 742 ns |
| ADMIN wildcard delete (allowed) | **10.1 ns** | 10.7 ns | 837 ns |
| VIEWER delete Post (denied) | **10.4 ns** | 12.4 ns | 580 ns |
| **1,000,000 ops — total time** | **11.9 ms** | 14.8 ms | 1,690 ms |
| **Throughput** | **~84M ops/sec** | ~67M ops/sec | ~590K ops/sec |

permzplus is **1.1–1.7× faster than CASL** and **42–89× faster than accesscontrol** across all scenarios, while offering hierarchical RBAC, ABAC conditions, audit logging, and query generation that neither library provides.

### How it's this fast

The hot path is a two-level Map lookup — **zero string allocation, zero regex**:

```
checkCache.get(role)?.get(permission)  →  return boolean
```

Cache entries are only written on the first call per `(role, permission)` pair (a cache miss). Every subsequent call costs exactly two hash-map lookups and a branch — nothing else is touched.

### Bundle size

| | permzplus | CASL | accesscontrol |
|---|---|---|---|
| Raw (minified) | **19.9 KB** | ~55 KB | ~35 KB |
| Gzip | **5.9 KB** | ~15 KB | ~10 KB |
| Dependencies | **0** | 3+ | 5+ |

> Run the benchmark yourself: `pnpm bench:compare`
> Source: [`bench/benchmark.ts`](bench/benchmark.ts)

---

## Installation

```bash
npm install permzplus
# or
pnpm add permzplus
```

---

## Core API

### Fluent Builder

```ts
import { createPermz, PolicyEngine } from 'permzplus'

const snapshot = createPermz({ name: 'ADMIN', level: 99 })
  .can('read',   'posts')
  .can('write',  'posts')
  .can('delete', 'posts')
  .build()

const policy = PolicyEngine.fromJSON(snapshot)
```

### Declarative (classic)

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

policy.can('ORG_ADMIN', 'sites:create')   // true — direct
policy.can('ORG_ADMIN', 'content:read')   // true — inherited from MEMBER
policy.can('MEMBER', 'billing:delete')    // false — explicit deny
policy.safeCan('', 'content:read')        // false — safe for unauthenticated users
```

---

## ABAC — Attribute-Based Conditions

### Object conditions (serializable)

MongoDB-style operators. Works with `can()` and with `accessibleBy()` for query generation.

```ts
// Only published posts
policy.defineRule('MEMBER', 'posts:read', { status: 'published' })

// Only the user's own posts — possession macro expands {{user.id}} at runtime
policy.defineRule('MEMBER', 'posts:edit', { authorId: '{{user.id}}' })

policy.can('MEMBER', 'posts:read', { status: 'published' }, { user: { id: 'u1' } })  // true
policy.can('MEMBER', 'posts:read', { status: 'draft' },     { user: { id: 'u1' } })  // false
```

### Function conditions

```ts
policy.defineRule('MEMBER', 'posts:edit',
  (post, ctx) => post.authorId === ctx?.userId && post.status !== 'locked'
)

policy.can('MEMBER', 'posts:edit', post, { userId: 'u1' })
```

### Possession Macros

Use `{{dot.path}}` in object conditions to inject runtime context values without writing a function. The path is resolved against the context object passed to `can()`.

```ts
policy.defineRule('MEMBER', 'posts:edit',    { authorId: '{{user.id}}' })
policy.defineRule('MEMBER', 'comments:edit', { authorId: '{{user.id}}', tenantId: '{{tenant.id}}' })
```

Mixed strings work too: `"org-{{tenant.id}}"` → `"org-acme"`.

### Supported Operators

Built-in: `$eq` `$ne` `$gt` `$gte` `$lt` `$lte` `$in` `$nin` `$exists` `$regex` `$and` `$or` `$nor`

Time operators: `$after` `$before` `$between`

```ts
policy.defineRule('MODERATOR', 'posts:delete', {
  status: { $in: ['flagged', 'spam'] },
  reportCount: { $gte: 3 },
})

policy.defineRule('MEMBER', 'events:rsvp', {
  startsAt: { $after: new Date() },
})
```

### Custom Operators

```ts
import { registerOperator } from 'permzplus'

registerOperator('$startsWith', (fieldValue, operand) =>
  typeof fieldValue === 'string' && fieldValue.startsWith(operand as string)
)

policy.defineRule('ADMIN', 'files:read', { path: { $startsWith: '/public/' } })
```

### Per-Request Context

```ts
const ctx = policy.createContext('MEMBER', { userId: req.user.id })

ctx.can('posts:edit', post)     // condition receives { userId: req.user.id }
ctx.cannot('posts:delete', post)
ctx.assert('posts:edit', post)  // throws PermissionDeniedError if denied
```

---

## Field-Level Permissions

```ts
policy.addRole({
  name: 'EDITOR',
  level: 2,
  permissions: ['post.title:edit', 'post.body:edit', 'post.status:read'],
})

policy.permittedFieldsOf('EDITOR', 'post', 'edit')  // ['title', 'body']
policy.permittedFieldsOf('EDITOR', 'post', 'read')  // ['status']
```

---

## Query Builder

`accessibleBy()` converts ABAC rules into database WHERE clauses — derive access filters directly from your policy.

```ts
import { accessibleBy } from 'permzplus/query'

const { permitted, unrestricted, conditions } = accessibleBy(policy, 'MEMBER', 'posts:read')

// Prisma
const posts = await prisma.post.findMany({
  where: !permitted ? { id: 'never' } : unrestricted ? {} : { OR: conditions },
})

// Mongoose
const posts = await Post.find(unrestricted ? {} : { $or: conditions })
```

### Multi-Role Merge

```ts
import { mergeAccessible } from 'permzplus/query'

const access = mergeAccessible(
  accessibleBy(policy, 'MEMBER',    'posts:read'),
  accessibleBy(policy, 'MODERATOR', 'posts:read'),
)
```

| Field | Type | Meaning |
|---|---|---|
| `permitted` | `boolean` | Role has this permission at all |
| `unrestricted` | `boolean` | Permitted with no conditions — return all records |
| `conditions` | `object[]` | MongoDB-style OR filter conditions |

---

## Permission Groups

Reuse sets of permissions across roles. Compose groups with `@ref` syntax — cycle detection is built in.

```ts
const policy = defineAbility(({ role, group }) => {
  group('content-viewer', ['posts:read', 'comments:read'])
  group('content-editor', ['@content-viewer', 'posts:write', 'comments:write'])

  role('MEMBER', 1, (can) => can('#content-viewer'))
  role('EDITOR', 2, (can) => can('#content-editor'))  // inherits viewer permissions
})
```

---

## Delegation & Impersonation

Temporarily elevate or transfer permissions — optionally scoped to a subset of the delegator's rules.

```ts
// Full delegation
const delegated = policy.delegate('ADMIN', 'temp-user-id')

// Scoped delegation — only these permissions are forwarded
const scoped = policy.delegate('ADMIN', 'temp-user-id', ['posts:read', 'posts:write'])
```

---

## Expiring Role Assignments

```ts
policy.assignRole('MEMBER', userId, {
  expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),  // 7 days
})

// Expired assignments are filtered automatically on every check
```

---

## Audit Logging

```ts
import { InMemoryAuditLogger } from 'permzplus'

const audit = new InMemoryAuditLogger()
const policy = new PolicyEngine({ audit })

policy.grantTo('MEMBER', 'posts:create')

// Simple access
audit.getEvents()                      // all events
audit.forUser('u1')                    // events for a specific user
audit.forRole('MEMBER')                // events for a specific role
audit.since(new Date('2025-01-01'))    // events since a date

// Composable queries
audit.query({
  action: 'permission.grant',
  role: 'MEMBER',
  since: new Date('2025-01-01'),
  order: 'desc',
  limit: 50,
})
```

---

## Import / Export

```ts
// Serialization — send over the wire
const snapshot = policy.toJSON()
const policy   = PolicyEngine.fromJSON(snapshot)

// CSV bulk import / export
const csv    = policy.toCSV()
const policy = await PolicyEngine.fromCSV(csvString)

// Bulk JSON import
await PolicyEngine.fromBulkJSON(jsonArray)
```

---

## Standalone Validator

```ts
import { validate } from 'permzplus/validator'

const issues = validate(snapshot)
// ValidationIssue types:
// orphaned_group | invalid_level | duplicate_level | invalid_permission | undefined_group_ref
```

---

## GraphQL

```ts
import { withPermission } from 'permzplus/adapters/graphql'

const resolvers = {
  Mutation: {
    deletePost: withPermission(policy, 'posts:delete', async (_, args, ctx) => {
      return deletePost(args.id)
    }),
  },
}
```

---

## tRPC

```ts
import { trpcPermission } from 'permzplus/adapters/trpc'

const protectedProcedure = t.procedure.use(trpcPermission(policy, 'posts:write'))
```

---

## Framework Adapters

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

```ts
import { PrismaAdapter }    from 'permzplus/adapters/prisma'
import { MongooseAdapter }  from 'permzplus/adapters/mongoose'
import { DrizzleAdapter }   from 'permzplus/adapters/drizzle'
import { FirebaseAdapter }  from 'permzplus/adapters/firebase'
import { SupabaseAdapter }  from 'permzplus/adapters/supabase'
import { RedisAdapter }     from 'permzplus/adapters/redis'
import { TypeORMAdapter }   from 'permzplus/adapters/typeorm'
import { KnexAdapter }      from 'permzplus/adapters/knex'
import { SequelizeAdapter } from 'permzplus/adapters/sequelize'

const policy = await PolicyEngine.fromAdapter(new PrismaAdapter(prisma))
```

---

## React

```tsx
import { PermissionProvider, useAbility, Can } from 'permzplus/react'

function App() {
  return (
    <PermissionProvider engine={policy} role={user.role ?? ''}>
      <Dashboard />
    </PermissionProvider>
  )
}

function EditButton({ post }) {
  const ability = useAbility()
  if (!ability.can('posts:edit', () => post.authorId === userId)) return null
  return <button>Edit</button>
}

// Declarative — CASL-style I/a props supported
function Toolbar() {
  return <Can I="delete" a="post"><DeleteButton /></Can>
}
```

---

## Vue

```ts
import { providePermissions, usePermission } from 'permzplus/vue'

providePermissions(policy, user.role)

const canDelete = usePermission('posts:delete')  // ComputedRef<boolean>
```

---

## Full-Stack — TypeScript + Python

permzplus is the only permissions library with a first-party FastAPI adapter. Define once, enforce everywhere.

```ts
// Frontend — TypeScript
const policy = defineAbility(({ role }) => {
  role('MEMBER', 1, (can) => can('posts:read', 'posts:edit'))
  role('ADMIN',  2, (can) => can('*'))
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

## Social Proof

- **230+ developers** using permzplus in production
- **100/100** [Socket.dev security score](https://socket.dev/npm/package/permzplus) — zero dependencies, zero supply chain risk
- **136 weekly downloads** and growing

---

## Spread the Word

If permzplus saves you time, help others find it:

- **Star the repo!** on [GitHub](https://github.com/Thundered-Studios/Permzplus) — it helps with discoverability
- **Share it!** with your team, in Discord servers, or on Twitter/X
- **Write about it!** — blog posts, dev.to articles, or Stack Overflow answers go a long way
- **Open issues or PRs!** — feedback and contributions make the library better for everyone

The project is solo-maintained (by a 12 year old). Every mention helps.

---

## License

MIT
