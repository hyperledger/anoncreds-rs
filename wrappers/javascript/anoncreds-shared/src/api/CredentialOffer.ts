import type { ObjectHandle } from '../ObjectHandle'
import type { JsonObject } from '../types'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

import { KeyCorrectnessProof } from './KeyCorrectnessProof'
import { pushToArray } from './utils'

export type CreateCredentialOfferOptions = {
  schemaId: string
  credentialDefinitionId: string
  keyCorrectnessProof: KeyCorrectnessProof | JsonObject
}

export class CredentialOffer extends AnoncredsObject {
  public static create(options: CreateCredentialOfferOptions) {
    const objectHandles: ObjectHandle[] = []
    try {
      const keyCorrectnessProof =
        options.keyCorrectnessProof instanceof KeyCorrectnessProof
          ? options.keyCorrectnessProof.handle
          : pushToArray(KeyCorrectnessProof.fromJson(options.keyCorrectnessProof).handle, objectHandles)

      return new CredentialOffer(
        anoncreds.createCredentialOffer({
          schemaId: options.schemaId,
          credentialDefinitionId: options.credentialDefinitionId,
          keyCorrectnessProof,
        }).handle
      )
    } finally {
      objectHandles.forEach((handle) => handle.clear())
    }
  }

  public static fromJson(json: JsonObject) {
    return new CredentialOffer(anoncreds.credentialOfferFromJson({ json: JSON.stringify(json) }).handle)
  }
}
