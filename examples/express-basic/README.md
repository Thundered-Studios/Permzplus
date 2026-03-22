# permzplus-express-example

A minimal Express app that demonstrates the core features of [Permzplus](../../README.md):

- Loading built-in hierarchical roles (`GUEST`, `USER`, `MODERATOR`, `ADMIN`, `SUPER_ADMIN`)
- Adding a custom role (`TESTER`) with its own permissions
- Protecting routes with `expressGuard` middleware
- How role level inheritance controls access (a MODERATOR automatically has all USER and GUEST permissions)

## Running

```bash
node index.js
```

The server starts on **http://localhost:3000**.

## Testing with curl

```bash
# Public route — always works, no role required
curl http://localhost:3000/

# GUEST can read posts (posts:read is the first permission on the hierarchy)
curl -H "x-role: GUEST" http://localhost:3000/posts

# USER cannot delete posts — 403 Forbidden
curl -X DELETE -H "x-role: USER" http://localhost:3000/posts/42

# MODERATOR can delete posts (level 40 inherits posts:delete)
curl -X DELETE -H "x-role: MODERATOR" http://localhost:3000/posts/42

# ADMIN can access the admin panel (admin:panel is granted at level 80)
curl -H "x-role: ADMIN" http://localhost:3000/admin

# SUPER_ADMIN has the wildcard permission and can reach every route
curl -H "x-role: SUPER_ADMIN" http://localhost:3000/superadmin

# Custom TESTER role (level 15) inherits GUEST permissions, so posts:read works
curl -H "x-role: TESTER" http://localhost:3000/posts
```

## How it works

`expressGuard(policy, 'permission:name')` returns a standard Express middleware function.
It reads `req.user.role` (set by the fake auth middleware in this example) and calls
`policy.assert(role, permission)`. If the assertion fails it responds with `403 Forbidden`;
if no role is present it responds with `401 Unauthorized`.
