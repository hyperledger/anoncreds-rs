import type { IndyCredxErrorObject } from 'indy-credx-shared'

import { IndyCredxError } from 'indy-credx-shared'

import { allocateStringBuffer } from './ffi'
import { nativeIndyCredx } from './library'

export const handleError = () => {
  const nativeError = allocateStringBuffer()
  nativeIndyCredx.credx_get_current_error(nativeError)
  const indyCredxErrorObject = JSON.parse(nativeError.deref() as string) as IndyCredxErrorObject

  if (indyCredxErrorObject.code === 0) return

  throw new IndyCredxError(indyCredxErrorObject)
}
