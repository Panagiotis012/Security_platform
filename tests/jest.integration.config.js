/** @type {import('jest').Config} */
module.exports = {
  displayName: 'integration',
  // Keep all relative paths anchored to this `tests/` folder even when Jest is
  // invoked from the repo root.
  rootDir: __dirname,
  testMatch: ['<rootDir>/integration/**/*.test.ts'],
  transform: {
    '^.+\\.tsx?$': ['ts-jest', { tsconfig: '<rootDir>/../tsconfig.json' }],
  },
  testTimeout: 60000,
  verbose: true,
};
