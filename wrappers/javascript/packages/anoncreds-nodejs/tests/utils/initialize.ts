import { registerAnoncreds } from '@hyperledger/anoncreds-shared'

import { NodeJSAnoncreds } from '../../src/NodeJSAnoncreds'

export const setup = () => registerAnoncreds({ lib: new NodeJSAnoncreds() })
