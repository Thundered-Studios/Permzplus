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
    // Framework guards
    "adapters/fastify": "src/adapters/fastify.ts",
    "adapters/hono": "src/adapters/hono.ts",
    "adapters/nest": "src/adapters/nest.ts",
    // UI framework integrations
    "react": "src/react.ts",
    "vue": "src/vue.ts",
  },
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  // Treat UI framework peer deps as external
  external: ["react", "vue"],
});
