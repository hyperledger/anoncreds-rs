import type { AnoncredsErrorObject } from '@hyperledger/anoncreds-shared'

import { AnoncredsError } from '@hyperledger/anoncreds-shared'

import { allocateStringBuffer } from './ffi'
import { getNativeAnoncreds } from './library'

export const handleError = () => {
  const nativeError = allocateStringBuffer()
  getNativeAnoncreds().anoncreds_get_current_error(nativeError)
  const anoncredsErrorObject = JSON.parse(nativeError.deref() as string) as AnoncredsErrorObject

  if (anoncredsErrorObject.code === 0) return

  throw new AnoncredsError(anoncredsErrorObject)
}
