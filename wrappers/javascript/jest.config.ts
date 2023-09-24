import type { JestConfigWithTsJest } from 'ts-jest'

const config: JestConfigWithTsJest = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  transform: {
    '^.+\\.ts$': [
      'ts-jest',
      {
        tsconfig: 'tsconfig.test.json',
        isolatedModules: true
      }
    ]
  },
  moduleNameMapper: {
    '@hyperledger/anoncreds-shared': '<rootDir>/packages/anoncreds-shared/src'
  }
}

module.exports = config
