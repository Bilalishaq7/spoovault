import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: [
      'src/__tests__/**/*.test.ts',
      'src/__tests__/VirtualizedDocumentsList.test.tsx',
      'src/__tests__/VirtualizedNftGrid.test.tsx',
      'src/__tests__/AuditLogTimeline.test.tsx',
    ],
    globals: true,
    pool: 'forks',
    forks: {
      singleFork: true,
    },
  },
});
