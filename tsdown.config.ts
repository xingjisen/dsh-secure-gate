import { defineConfig } from 'tsdown'

export default defineConfig({
  entry: ['./src/server/index.ts', './src/client/index.tsx'],
  format: 'esm',
  target: 'node22',
  clean: true,
  dts: true,
  external: ['@deepseek-ai/cordis', 'node:crypto', 'node:fs', 'node:path']
})
