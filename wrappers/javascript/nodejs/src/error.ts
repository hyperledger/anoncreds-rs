import type { AnoncredsErrorObject } from 'anoncreds-shared'

import { AnoncredsError } from 'anoncreds-shared'

import { allocateStringBuffer } from './ffi'
import { nativeAnoncreds } from './library'

export const handleError = () => {
  const nativeError = allocateStringBuffer()
  nativeAnoncreds.anoncreds_get_current_error(nativeError)
  const anoncredsErrorObject = JSON.parse(nativeError.deref() as string) as AnoncredsErrorObject

  if (anoncredsErrorObject.code === 0) return

  throw new AnoncredsError(anoncredsErrorObject)
}
