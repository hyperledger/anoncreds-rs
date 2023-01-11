import { NativeModules } from 'react-native'

type Module = {
  install: () => boolean
}

const module = NativeModules.IndyCredx as Module
if (!module.install()) throw Error('Unable to install the turboModule: IndyCredx')

export * from 'indy-credx-shared'

export { ReactNativeIndyCredx } from './ReactNativeIndyCredx'
