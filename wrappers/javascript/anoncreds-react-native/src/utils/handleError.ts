import type { ReturnObject } from './serialize'
import type { AnoncredsErrorObject } from '@hyperledger/anoncreds-shared'

import { anoncreds, AnoncredsError } from '@hyperledger/anoncreds-shared'

export const handleError = <T>({ errorCode, value }: ReturnObject<T>): T => {
  if (errorCode !== 0) {
    throw new AnoncredsError(JSON.parse(anoncreds.getCurrentError()) as AnoncredsErrorObject)
  }

  return value as T
}
