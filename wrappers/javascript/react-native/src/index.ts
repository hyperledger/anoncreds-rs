import { NativeModules } from 'react-native'

type Module = {
  install: () => boolean
}

const module = NativeModules.Anoncreds as Module
if (!module.install()) throw Error('Unable to install the turboModule: Anoncreds')

export * from 'anoncreds-shared'

export { ReactNativeAnoncreds } from './ReactNativeAnoncreds'
