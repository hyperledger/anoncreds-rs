import type { ObjectHandle } from '../ObjectHandle'
import type { JsonObject } from '../types'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

import { KeyCorrectnessProof } from './KeyCorrectnessProof'
import { pushToArray } from './utils'

export type CreateW3cCredentialOfferOptions = {
  schemaId: string
  credentialDefinitionId: string
  keyCorrectnessProof: KeyCorrectnessProof | JsonObject
}

export class W3cCredentialOffer extends AnoncredsObject {
  public static create(options: CreateW3cCredentialOfferOptions) {
    let credentialOfferHandle
    // Objects created within this method must be freed up
    const objectHandles: ObjectHandle[] = []
    try {
      const keyCorrectnessProof =
        options.keyCorrectnessProof instanceof KeyCorrectnessProof
          ? options.keyCorrectnessProof.handle
          : pushToArray(KeyCorrectnessProof.fromJson(options.keyCorrectnessProof).handle, objectHandles)

      credentialOfferHandle = anoncreds.createW3cCredentialOffer({
        schemaId: options.schemaId,
        credentialDefinitionId: options.credentialDefinitionId,
        keyCorrectnessProof
      }).handle
    } finally {
      objectHandles.forEach((handle) => {
        handle.clear()
      })
    }
    return new W3cCredentialOffer(credentialOfferHandle)
  }

  public static fromJson(json: JsonObject) {
    return new W3cCredentialOffer(anoncreds.w3cCredentialOfferFromJson({ json: JSON.stringify(json) }).handle)
  }
}
