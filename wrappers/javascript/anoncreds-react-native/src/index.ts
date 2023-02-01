import { registerAnoncreds } from '@hyperledger/anoncreds-shared'
import { NativeModules } from 'react-native'

import { ReactNativeAnoncreds } from './ReactNativeAnoncreds'

type Module = {
  install: () => boolean
}

const module = NativeModules.Anoncreds as Module
if (!module || !module.install || !module.install()) throw Error('Unable to install the turboModule: Anoncreds')

export * from '@hyperledger/anoncreds-shared'

export const anoncredsReactNative = new ReactNativeAnoncreds()
registerAnoncreds({ lib: anoncredsReactNative })
