import type { NativeBindings } from './NativeBindings'

// This can already check whether `_indy_credx` exists on global
// eslint-disable-next-line @typescript-eslint/no-use-before-define
if (!_indy_credx) {
  throw Error('_indy_credx has not been exposed on global. Something went wrong while installing the turboModule')
}

declare let _indy_credx: NativeBindings

// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
export const indyCredxReactNative = _indy_credx
