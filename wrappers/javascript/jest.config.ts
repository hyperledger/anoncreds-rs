import type { Config } from '@jest/types'

import base from './jest.config.base'

const config: Config.InitialOptions = {
  ...base,
  roots: ['<rootDir>'],
  projects: ['<rootDir>/anoncreds-nodejs', '<rootDir>/anoncreds-shared', '<rootDir>/anoncreds-react-native'],
}

export default config
