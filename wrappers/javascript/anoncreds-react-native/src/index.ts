// This will be fixed when we rename
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import { NativeModules } from 'react-native'

type Module = {
  install: () => boolean
}

// eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
const module = NativeModules.Anoncreds as Module
if (!module.install()) throw Error('Unable to install the turboModule: Anoncreds')

export * from '@hyperledger/anoncreds-shared'

export { ReactNativeAnoncreds } from './ReactNativeAnoncreds'
