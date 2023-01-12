import type { Config } from '@jest/types'

import base from './jest.config.base'

const config: Config.InitialOptions = {
  ...base,
  roots: ['<rootDir>'],
  projects: ['<rootDir>/nodejs', '<rootDir>/shared', '<rootDir>/react-native'],
}

export default config
