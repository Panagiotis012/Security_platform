/** @type {import('jest').Config} */
module.exports = {
  displayName: 'security',
  // Keep all relative paths anchored to this `tests/` folder even when Jest is
  // invoked from the repo root.
  rootDir: __dirname,
  testMatch: ['<rootDir>/security/**/*.test.ts'],
  transform: {
    '^.+\\.tsx?$': ['ts-jest', { tsconfig: '<rootDir>/../tsconfig.json' }],
  },
  testTimeout: 30000,
  verbose: true,
};
