import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    // Core
    "index": "src/index.ts",
    // Generic + Express + Next.js guards
    "guard": "src/guard.ts",
    // DB adapters
    "adapters/prisma": "src/adapters/prisma.ts",
    "adapters/mongoose": "src/adapters/mongoose.ts",
    "adapters/drizzle": "src/adapters/drizzle.ts",
    "adapters/memory": "src/adapters/memory.ts",
    "adapters/firebase": "src/adapters/firebase.ts",
    "adapters/supabase": "src/adapters/supabase.ts",
    "adapters/redis": "src/adapters/redis.ts",
    "adapters/typeorm": "src/adapters/typeorm.ts",
    "adapters/knex": "src/adapters/knex.ts",
    "adapters/sequelize": "src/adapters/sequelize.ts",
    // Framework guards
    "adapters/fastify": "src/adapters/fastify.ts",
    "adapters/graphql": "src/adapters/graphql.ts",
    "adapters/trpc": "src/adapters/trpc.ts",
    "adapters/hono": "src/adapters/hono.ts",
    "adapters/nest": "src/adapters/nest.ts",
    // UI framework integrations
    "react": "src/react.ts",
    "vue": "src/vue.ts",
    // Next.js App Router integration
    "nextjs": "src/nextjs.ts",
    "nextjs/client": "src/nextjs-client.ts",
    "nextjs/middleware": "src/nextjs-middleware.ts",
    // Bitmask serialization (shared, Edge-safe)
    "bitmask": "src/bitmask.ts",
    // Query builder (ABAC → database WHERE clauses)
    "query": "src/query.ts",
    // Testing utilities (not included in main bundle)
    "testing": "src/testing.ts",
    // Policy validator (separate export — tree-shakes out of prod bundles)
    "validator": "src/validator.ts",
  },
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  // Minify output — removes whitespace, mangles local identifiers, drops dead
  // branches. Keeps the core index.js as small as possible on disk.
  minify: true,
  // CJS → .cjs, ESM → .js (matches package.json "exports" expectations)
  outExtension({ format }) {
    return { js: format === 'cjs' ? '.cjs' : '.js' }
  },
  // Treat UI framework peer deps as external so they never bloat the core.
  // All adapters are separate entry points; they cannot leak into index.js.
  external: ["react", "vue", "firebase"],
});
