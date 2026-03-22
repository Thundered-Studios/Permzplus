import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    "index": "src/index.ts",
    "guard": "src/guard.ts",
    "adapters/prisma": "src/adapters/prisma.ts",
    "adapters/mongoose": "src/adapters/mongoose.ts",
    "adapters/drizzle": "src/adapters/drizzle.ts",
  },
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
});
