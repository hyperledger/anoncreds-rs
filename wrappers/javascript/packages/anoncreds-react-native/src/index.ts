import { registerAnoncreds } from '@hyperledger/anoncreds-shared'

import { ReactNativeAnoncreds } from './ReactNativeAnoncreds'
import { register } from './register'

export * from '@hyperledger/anoncreds-shared'

registerAnoncreds({ lib: new ReactNativeAnoncreds(register()) })
