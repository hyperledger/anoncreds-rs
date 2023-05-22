import type { NativeBindings } from './NativeBindings'

import { registerAnoncreds } from '@hyperledger/anoncreds-shared'
import { NativeModules } from 'react-native'

import { ReactNativeAnoncreds } from './ReactNativeAnoncreds'

export * from '@hyperledger/anoncreds-shared'

const module = NativeModules.Anoncreds as { install: () => boolean }
if (!module || !module.install || !module.install()) throw Error('Unable to install the turboModule: Anoncreds')

// This can already check whether `_anoncreds` exists on global
// eslint-disable-next-line @typescript-eslint/no-use-before-define
if (!_anoncreds) {
  throw Error('_anoncreds has not been exposed on global. Something went wrong while installing the turboModule')
}

declare let _anoncreds: NativeBindings

registerAnoncreds({ lib: new ReactNativeAnoncreds(_anoncreds) })
