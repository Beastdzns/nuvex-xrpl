import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    testTimeout: 60000,
    setupFiles: ['dotenv/config'],
    include: ['__tests__/**/*.{test,spec}.{js,ts}'],
    exclude: ['node_modules', 'dist', 'bridge-service/node_modules']
  },
  resolve: {
    alias: {
      '@': new URL('./src', import.meta.url).pathname,
      '@tests': new URL('./__tests__', import.meta.url).pathname
    }
  }
})
