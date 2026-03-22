/**
 * Permzplus Express Example
 *
 * Demonstrates role-based access control with permzplus in an Express app.
 *
 * Quick curl tests (run after `node index.js`):
 *
 *   # Public route — no role required
 *   curl http://localhost:3000/
 *
 *   # GUEST can read posts (level 0, has posts:read)
 *   curl -H "x-role: GUEST" http://localhost:3000/posts
 *
 *   # USER cannot delete posts (requires MODERATOR level 40+)
 *   curl -X DELETE -H "x-role: USER" http://localhost:3000/posts/42
 *
 *   # MODERATOR can delete posts (level 40, inherits posts:delete)
 *   curl -X DELETE -H "x-role: MODERATOR" http://localhost:3000/posts/42
 *
 *   # ADMIN can access the admin panel (level 80, has admin:panel)
 *   curl -H "x-role: ADMIN" http://localhost:3000/admin
 *
 *   # Only SUPER_ADMIN reaches /superadmin (admin:debug requires level 60+, but
 *   # DEVELOPER also has it — SUPER_ADMIN is the highest level at 100)
 *   curl -H "x-role: SUPER_ADMIN" http://localhost:3000/superadmin
 *
 *   # Custom TESTER role can run tests (level 15, has tests:run)
 *   curl -H "x-role: TESTER" http://localhost:3000/posts
 */

import express from 'express'
import { PolicyEngine } from 'permzplus'
import { expressGuard } from 'permzplus/guard'

// ── 1. Set up the policy engine ───────────────────────────────────────────────
//
// new PolicyEngine() automatically loads all built-in roles:
//   GUEST (0)  → posts:read
//   USER (20)  → posts:read, posts:write, comments:read, comments:write
//   MODERATOR (40) → posts:delete, comments:delete, users:warn  (+ inherits USER)
//   DEVELOPER (60) → admin:debug, admin:logs  (+ inherits MODERATOR)
//   ADMIN (80) → users:ban, users:delete, admin:panel  (+ inherits DEVELOPER)
//   SUPER_ADMIN (100) → *  (wildcard — can do anything)

const policy = new PolicyEngine()

// ── 2. Register a custom role ─────────────────────────────────────────────────
//
// Levels are arbitrary numbers. Level 15 sits between GUEST (0) and USER (20),
// so TESTER inherits GUEST's permissions plus its own tests:run grant.

policy.addRole({ name: 'TESTER', level: 15, permissions: ['tests:run'] })

// ── 3. Create the Express app ─────────────────────────────────────────────────

const app = express()
app.use(express.json())

// ── 4. Fake auth middleware ───────────────────────────────────────────────────
//
// In a real app this would verify a JWT or session cookie and populate req.user
// from the database. Here we just trust the x-role header for demo purposes.

app.use((req, _res, next) => {
  const role = req.headers['x-role']
  if (role) {
    req.user = { role: String(role) }
  }
  next()
})

// ── 5. Routes ─────────────────────────────────────────────────────────────────

// Public — no guard, anyone can hit this.
app.get('/', (_req, res) => {
  res.json({ message: 'Hello from Permzplus example' })
})

// Requires posts:read — GUEST (level 0) already has this, so every valid role
// can access it. Sending no x-role header returns 401.
app.get('/posts', expressGuard(policy, 'posts:read'), (_req, res) => {
  res.json({ posts: [{ id: 1, title: 'Hello World' }, { id: 2, title: 'Permzplus Rocks' }] })
})

// Requires posts:delete — granted at MODERATOR level (40). USER (20) is denied.
app.delete('/posts/:id', expressGuard(policy, 'posts:delete'), (req, res) => {
  res.json({ message: `Post ${req.params.id} deleted`, deletedBy: req.user?.role })
})

// Requires admin:panel — granted at ADMIN level (80).
app.get('/admin', expressGuard(policy, 'admin:panel'), (_req, res) => {
  res.json({ message: 'Welcome to the admin panel' })
})

// Requires admin:debug — granted starting at DEVELOPER level (60).
// In practice only DEVELOPER, ADMIN, and SUPER_ADMIN can reach this.
// Add denyFrom calls if you want to restrict it to SUPER_ADMIN exclusively.
app.get('/superadmin', expressGuard(policy, 'admin:debug'), (_req, res) => {
  res.json({ message: 'Super-admin debug area', role: _req.user?.role })
})

// ── 6. Start the server ───────────────────────────────────────────────────────

const PORT = 3000

app.listen(PORT, () => {
  console.log(`Permzplus Express example running on http://localhost:${PORT}`)
  console.log()
  console.log('Try these curl commands:')
  console.log(`  curl http://localhost:${PORT}/`)
  console.log(`  curl -H "x-role: GUEST"       http://localhost:${PORT}/posts`)
  console.log(`  curl -H "x-role: USER"         http://localhost:${PORT}/posts`)
  console.log(`  curl -X DELETE -H "x-role: USER"      http://localhost:${PORT}/posts/1`)
  console.log(`  curl -X DELETE -H "x-role: MODERATOR" http://localhost:${PORT}/posts/1`)
  console.log(`  curl -H "x-role: ADMIN"        http://localhost:${PORT}/admin`)
  console.log(`  curl -H "x-role: SUPER_ADMIN"  http://localhost:${PORT}/superadmin`)
  console.log(`  curl -H "x-role: TESTER"       http://localhost:${PORT}/posts`)
})
