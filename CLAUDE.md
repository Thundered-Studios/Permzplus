# Permzplus — Claude Project Guide

## What is Permzplus?

Permzplus is a TypeScript-first NPM library for managing hierarchical role-based permissions in web applications. It supports built-in role tiers (e.g., `SUPER_ADMIN`, `ADMIN`, `MODERATOR`, `DEVELOPER`, `USER`), custom roles, per-resource permission scoping, middleware integration, and runtime permission checks — all with a minimal, chainable API.

---

## Tech Stack

| Layer | Choice | Reason |
|---|---|---|
| Language | TypeScript | Type safety, autocomplete, first-class `.d.ts` output |
| Build tool | tsup | Zero-config, outputs ESM + CJS + types in one command |
| Test runner | Vitest | Fast, TS-native, compatible with Node |
| Lint / Format | ESLint + Prettier | Standard toolchain |
| Package manager | pnpm | Fast, strict, workspace-ready |
| CI | GitHub Actions | Auto-test and publish on tag push |
| Registry | npmjs.com | Public package: `permzplus` |

---

## Project Structure

```
permzplus/
├── src/
│   ├── index.ts              # Public API barrel export
│   ├── roles.ts              # Built-in role definitions + hierarchy
│   ├── permissions.ts        # Permission node definitions + checks
│   ├── policy.ts             # PolicyEngine — combines roles + permissions
│   ├── guard.ts              # Guard / middleware helpers (Express, generic)
│   ├── context.ts            # PermissionContext — per-request scoping
│   ├── adapter.ts            # PermzAdapter interface + base class
│   ├── errors.ts             # Typed error classes
│   └── types.ts              # All shared TypeScript types/interfaces
├── adapters/
│   ├── prisma.ts             # Prisma adapter (peer dep: @prisma/client)
│   ├── mongoose.ts           # Mongoose adapter (peer dep: mongoose)
│   ├── drizzle.ts            # Drizzle adapter (peer dep: drizzle-orm)
│   └── memory.ts             # In-memory adapter (default, no deps)
├── tests/
│   ├── roles.test.ts
│   ├── permissions.test.ts
│   ├── policy.test.ts
│   ├── adapter.test.ts
│   └── guard.test.ts
├── examples/
│   ├── express-basic/        # Express.js integration example
│   ├── nextjs-middleware/    # Next.js middleware example
│   ├── prisma-adapter/       # Prisma DB integration example
│   └── custom-adapter/       # Example of a hand-rolled adapter
├── CLAUDE.md
├── README.md
├── package.json
├── tsconfig.json
├── tsup.config.ts
└── vitest.config.ts
```

---

## Core Concepts

### 1. Roles

Permzplus ships with a set of built-in roles out of the box. These are ready to use with no configuration:

```
SUPER_ADMIN  (level 100)  — full wildcard access, cannot be restricted
ADMIN        (level 80)   — user management, panel access, moderation
DEVELOPER    (level 60)   — internal tooling, debug access
MODERATOR    (level 40)   — content moderation, warn/mute users
USER         (level 20)   — standard authenticated access
GUEST        (level 0)    — read-only, unauthenticated
```

Built-in roles and their default permissions are defined in `src/roles.ts` and are always registered first. They can be extended (add permissions) but not deleted.

**Custom roles** can be registered at any numeric level, including between built-in roles:

```ts
policy.addRole('TRIAL_USER', 15, ['posts:read', 'comments:read']);
policy.addRole('SENIOR_MOD', 50, ['users:ban']);
```

Custom roles participate in inheritance exactly like built-in ones. Role comparison is purely numeric — higher level = more privilege.

### 2. Permissions

Permissions are string identifiers in `resource:action` format. Examples:
- `posts:read`
- `posts:write`
- `users:ban`
- `admin:panel`
- `*` (wildcard — matches all)

Permissions can be:
- **Granted** to a role explicitly
- **Inherited** automatically from lower roles in the hierarchy
- **Denied** explicitly (deny overrides grant, useful for edge cases)

### 3. PolicyEngine

The `PolicyEngine` is the central object. It is initialized with a role hierarchy and permission map, then used to evaluate whether a given role can perform an action.

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

policy.can('MODERATOR', 'posts:read');   // true (inherited)
policy.can('USER', 'users:ban');          // false
policy.can('SUPER_ADMIN', 'anything');   // true (wildcard)
```

### 4. PermissionContext (per-request scoping)

A `PermissionContext` is a short-lived object created per request. It binds a role (and optionally a user ID or resource ID) so checks don't require re-passing the role everywhere.

```ts
const ctx = policy.createContext({ role: 'MODERATOR', userId: '123' });
ctx.can('posts:delete');  // true
ctx.assert('users:ban');  // throws PermissionDeniedError
```

### 5. DB Adapter (Persistence Layer)

Permzplus ships with a DB-agnostic adapter interface. This allows roles and permissions to be loaded from and synced to any database at runtime — without coupling the core engine to any specific ORM or driver.

**Adapter interface:**

```ts
interface PermzAdapter {
  getRoles(): Promise<RoleDefinition[]>;
  getPermissions(role: string): Promise<string[]>;
  saveRole(role: RoleDefinition): Promise<void>;
  deleteRole(role: string): Promise<void>;
  grantPermission(role: string, permission: string): Promise<void>;
  revokePermission(role: string, permission: string): Promise<void>;
}
```

**Usage:**

```ts
import { PolicyEngine } from 'permzplus';
import { PrismaAdapter } from 'permzplus/adapters/prisma';

const policy = await PolicyEngine.fromAdapter(new PrismaAdapter(prisma));
```

`PolicyEngine.fromAdapter()` calls `adapter.getRoles()` and `adapter.getPermissions()` at startup to hydrate the in-memory policy, then delegates any mutations (`addRole`, `grantTo`, `denyFrom`) to both the in-memory state and the adapter simultaneously.

**Built-in adapters (separate entry points, optional peer deps):**

| Adapter | Entry point | Peer dep |
|---|---|---|
| Prisma | `permzplus/adapters/prisma` | `@prisma/client` |
| Mongoose | `permzplus/adapters/mongoose` | `mongoose` |
| Drizzle | `permzplus/adapters/drizzle` | `drizzle-orm` |
| In-memory (default) | built into core | none |

**Custom adapter:** any object satisfying `PermzAdapter` works — no class extension required. This covers raw `pg`, Supabase, Firebase, Redis, REST APIs, etc.

Built-in roles are always seeded into the DB on first `fromAdapter()` call if they don't already exist, so the DB stays in sync with the code defaults.

### 6. Guard / Middleware

Pre-built guard factories for common frameworks:

```ts
// Express
import { expressGuard } from 'permzplus/guard';

app.delete('/posts/:id', expressGuard(policy, 'posts:delete'), handler);

// Generic (works with any framework)
import { createGuard } from 'permzplus/guard';

const guard = createGuard(policy);
guard({ role: 'USER', permission: 'posts:delete' }); // throws or returns false
```

---

## API Reference Plan

### `PolicyEngine`

| Method | Signature | Description |
|---|---|---|
| `can` | `(role, permission) => boolean` | Check if role has permission |
| `cannot` | `(role, permission) => boolean` | Inverse of `can` |
| `assert` | `(role, permission) => void` | Throws `PermissionDeniedError` if not allowed |
| `getRoleLevel` | `(role) => number` | Returns numeric level of a role |
| `isAtLeast` | `(role, minRole) => boolean` | True if role level >= minRole level |
| `createContext` | `(opts) => PermissionContext` | Creates a scoped context object |
| `addRole` | `(role, level, permissions) => this` | Dynamically add a role |
| `grantTo` | `(role, permission) => this` | Add permission to existing role |
| `denyFrom` | `(role, permission) => this` | Explicitly deny a permission (overrides inheritance) |

### `PermissionContext`

| Method | Signature | Description |
|---|---|---|
| `can` | `(permission) => boolean` | Check with bound role |
| `cannot` | `(permission) => boolean` | Inverse |
| `assert` | `(permission) => void` | Throws if not allowed |
| `isAtLeast` | `(minRole) => boolean` | Role level check |

### Error Classes (`permzplus/errors`)

| Class | When thrown |
|---|---|
| `PermissionDeniedError` | `assert()` fails due to insufficient permission |
| `UnknownRoleError` | A role string is not registered in the policy |
| `InvalidPermissionError` | A permission string is malformed |

---

## Implementation Plan (Phases)

### Phase 1 — Scaffold
- [ ] Init repo with `pnpm init`, configure TypeScript, tsup, Vitest, ESLint, Prettier
- [ ] Set up `package.json` with correct `exports` (ESM + CJS), `types`, `files` fields
- [ ] Create `tsconfig.json` targeting ES2020, `moduleResolution: bundler`
- [ ] Add `tsup.config.ts` building `src/index.ts` and `src/guard.ts` as separate entry points
- [ ] Add GitHub Actions workflow: lint + test on PR, publish on `v*` tag push

### Phase 2 — Core Logic
- [ ] `types.ts` — define `Role`, `Permission`, `PolicyOptions`, `ContextOptions`, `PermzAdapter` interfaces
- [ ] `roles.ts` — built-in role map with numeric levels and default permissions; `registerRole`, `getRoleLevel`, `isAtLeast`
- [ ] `permissions.ts` — permission string parsing, wildcard matching, deny-list logic
- [ ] `policy.ts` — `PolicyEngine` class; in-memory role/permission store, inheritance resolution, `PolicyEngine.fromAdapter()`
- [ ] `adapter.ts` — `PermzAdapter` interface; `InMemoryAdapter` default implementation
- [ ] `errors.ts` — `PermissionDeniedError`, `UnknownRoleError`, `InvalidPermissionError`, `AdapterError`
- [ ] `context.ts` — `PermissionContext` bound to a role instance

### Phase 3 — DB Adapters
- [ ] `adapters/memory.ts` — in-memory adapter, used internally when no adapter is provided
- [ ] `adapters/prisma.ts` — Prisma adapter; expects a `roles` and `role_permissions` table schema (documented)
- [ ] `adapters/mongoose.ts` — Mongoose adapter; `Role` model with embedded permissions array
- [ ] `adapters/drizzle.ts` — Drizzle adapter; works with any Drizzle-supported DB (Postgres, SQLite, MySQL)
- [ ] Built-in roles seeded to DB automatically on first `fromAdapter()` call if absent

### Phase 4 — Middleware / Guards
- [ ] `guard.ts` — `createGuard` generic factory
- [ ] Express adapter (`expressGuard`) — reads role from `req.user.role` by default, configurable
- [ ] Next.js adapter — guard factory returning a middleware function compatible with `middleware.ts`

### Phase 5 — Tests
- [ ] Unit tests for role hierarchy and level comparison
- [ ] Unit tests for permission matching (exact, wildcard, deny override)
- [ ] Integration tests for `PolicyEngine` (inheritance, dynamic mutation)
- [ ] Tests for `PermissionContext`
- [ ] Tests for `InMemoryAdapter` and all built-in DB adapters (mocked clients)
- [ ] Tests for guard/middleware factories with mocked request objects

### Phase 6 — Examples & Docs
- [ ] `examples/express-basic/` — minimal Express app with role-protected routes
- [ ] `examples/nextjs-middleware/` — Next.js `middleware.ts` with route-level guards
- [ ] `examples/prisma-adapter/` — full Prisma setup with migration schema
- [ ] `examples/custom-adapter/` — annotated example of implementing `PermzAdapter` from scratch
- [ ] `README.md` — quick start, API table, role hierarchy diagram, DB adapter guide, FAQ

### Phase 6 — Publish
- [ ] Dry run: `pnpm publish --dry-run`
- [ ] Tag `v1.0.0`, push tag to trigger CI publish workflow
- [ ] Verify on npmjs.com and test install in a fresh project

---

## Key Design Decisions

**Inheritance is additive by default.** Each role gets its own permissions plus everything from roles below it. This is the most intuitive behavior for tiered systems and avoids needing to repeat permissions.

**Deny always wins.** An explicit `denyFrom(role, permission)` overrides inherited grants. This allows edge cases like "everyone except DEVELOPER can access billing" without restructuring the hierarchy.

**DB optional but first-class.** Out of the box the engine is in-memory. Plug in any adapter (`PrismaAdapter`, `MongooseAdapter`, `DrizzleAdapter`, or a custom one) and the policy syncs with the database automatically — both on load and on every mutation.

**Framework-agnostic core.** `src/index.ts` has zero runtime dependencies. Framework adapters live in separate entry points so tree-shaking is clean.

**String-based permissions.** `resource:action` format is human-readable, debuggable, and avoids enum hell. Wildcards (`*`, `posts:*`) are supported.

**Chainable mutations.** `addRole`, `grantTo`, `denyFrom` all return `this` so policies can be built fluently.

---

## package.json Shape (target)

```json
{
  "name": "permzplus",
  "version": "1.0.0",
  "description": "Hierarchical role-based permissions library for web apps",
  "keywords": ["permissions", "rbac", "roles", "authorization", "acl"],
  "main": "./dist/index.cjs",
  "module": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "exports": {
    ".": {
      "import": "./dist/index.js",
      "require": "./dist/index.cjs",
      "types": "./dist/index.d.ts"
    },
    "./guard": {
      "import": "./dist/guard.js",
      "require": "./dist/guard.cjs",
      "types": "./dist/guard.d.ts"
    },
    "./adapters/prisma": {
      "import": "./dist/adapters/prisma.js",
      "require": "./dist/adapters/prisma.cjs",
      "types": "./dist/adapters/prisma.d.ts"
    },
    "./adapters/mongoose": {
      "import": "./dist/adapters/mongoose.js",
      "require": "./dist/adapters/mongoose.cjs",
      "types": "./dist/adapters/mongoose.d.ts"
    },
    "./adapters/drizzle": {
      "import": "./dist/adapters/drizzle.js",
      "require": "./dist/adapters/drizzle.cjs",
      "types": "./dist/adapters/drizzle.d.ts"
    }
  },
  "peerDependencies": {
    "@prisma/client": ">=5.0.0",
    "mongoose": ">=7.0.0",
    "drizzle-orm": ">=0.29.0"
  },
  "peerDependenciesMeta": {
    "@prisma/client": { "optional": true },
    "mongoose": { "optional": true },
    "drizzle-orm": { "optional": true }
  },
  "files": ["dist"],
  "scripts": {
    "build": "tsup",
    "test": "vitest run",
    "lint": "eslint src tests",
    "prepublishOnly": "pnpm build && pnpm test"
  }
}
```

---

## Conventions for Claude

- All source lives in `src/`. No logic in `index.ts` — it only re-exports.
- Types are centralized in `types.ts`. Do not scatter interfaces across files.
- Every public method must have a JSDoc comment.
- Tests mirror the `src/` structure in `tests/`.
- Do not add external runtime dependencies without discussing first — the goal is zero deps in core.
- Permission strings must always be validated with `validatePermission()` from `permissions.ts` before use.
- Errors must always be instances of the typed error classes, never raw `throw new Error(...)`.
- When adding a framework middleware adapter, add it as a separate tsup entry point, not in the core barrel.
- DB adapters live in `adapters/` and are separate tsup entry points. Each adapter must guard its peer dep with a try/catch import and throw a helpful `AdapterError` if the peer dep is missing.
- Built-in roles (`SUPER_ADMIN`, `ADMIN`, `DEVELOPER`, `MODERATOR`, `USER`, `GUEST`) are defined as constants in `roles.ts` and must never be removed or have their levels changed — only permissions can be extended.
- Custom roles are always user-defined via `addRole()` or via the DB adapter. Never hard-code consumer roles in the library.
- `PolicyEngine.fromAdapter()` is async. The synchronous constructor is always in-memory only. Do not make the constructor async.
