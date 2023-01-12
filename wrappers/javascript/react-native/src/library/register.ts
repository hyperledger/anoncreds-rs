import type { NativeBindings } from './NativeBindings'

// This can already check whether `_anoncreds` exists on global
// eslint-disable-next-line @typescript-eslint/no-use-before-define
if (!_anoncreds) {
  throw Error('_anoncreds has not been exposed on global. Something went wrong while installing the turboModule')
}

declare let _anoncreds: NativeBindings

export const anoncredsReactNative = _anoncreds
