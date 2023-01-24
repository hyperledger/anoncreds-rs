import { registerAnoncreds } from '@hyperledger/anoncreds-shared'

import { NodeJSAnoncreds } from './NodeJSAnoncreds'

export const anoncredsNodeJS = new NodeJSAnoncreds()
registerAnoncreds({ lib: anoncredsNodeJS })

export * from '@hyperledger/anoncreds-shared'
