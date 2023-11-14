import type { ObjectHandle } from '../ObjectHandle'
import type { JsonObject } from '../types'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

import { KeyCorrectnessProof } from './KeyCorrectnessProof'
import { pushToArray } from './utils'

export type CreateW3CCredentialOfferOptions = {
  schemaId: string
  credentialDefinitionId: string
  keyCorrectnessProof: KeyCorrectnessProof | JsonObject
}

export class W3CCredentialOffer extends AnoncredsObject {
  public static create(options: CreateW3CCredentialOfferOptions) {
    let credentialOfferHandle
    // Objects created within this method must be freed up
    const objectHandles: ObjectHandle[] = []
    try {
      const keyCorrectnessProof =
        options.keyCorrectnessProof instanceof KeyCorrectnessProof
          ? options.keyCorrectnessProof.handle
          : pushToArray(KeyCorrectnessProof.fromJson(options.keyCorrectnessProof).handle, objectHandles)

      credentialOfferHandle = anoncreds.createW3CCredentialOffer({
        schemaId: options.schemaId,
        credentialDefinitionId: options.credentialDefinitionId,
        keyCorrectnessProof
      }).handle
    } finally {
      objectHandles.forEach((handle) => {
        handle.clear()
      })
    }
    return new W3CCredentialOffer(credentialOfferHandle)
  }

  public static fromJson(json: JsonObject) {
    return new W3CCredentialOffer(anoncreds.w3cCredentialOfferFromJson({ json: JSON.stringify(json) }).handle)
  }
}
