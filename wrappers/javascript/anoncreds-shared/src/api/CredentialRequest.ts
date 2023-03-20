import type { ObjectHandle } from '../ObjectHandle'
import type { JsonObject } from '../types'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

import { CredentialDefinition } from './CredentialDefinition'
import { CredentialOffer } from './CredentialOffer'
import { CredentialRequestMetadata } from './CredentialRequestMetadata'
import { pushToArray } from './utils'

export type CreateCredentialRequestOptions = {
  entropy?: string
  proverDid?: string
  credentialDefinition: CredentialDefinition | JsonObject
  linkSecret: string
  linkSecretId: string
  credentialOffer: CredentialOffer | JsonObject
}

export class CredentialRequest extends AnoncredsObject {
  public static create(options: CreateCredentialRequestOptions) {
    let createReturnObj: {
      credentialRequest: ObjectHandle
      credentialRequestMetadata: ObjectHandle
    }
    // Objects created within this method must be freed up
    const objectHandles: ObjectHandle[] = []
    try {
      const credentialDefinition =
        options.credentialDefinition instanceof CredentialDefinition
          ? options.credentialDefinition.handle
          : pushToArray(CredentialDefinition.fromJson(options.credentialDefinition).handle, objectHandles)

      const credentialOffer =
        options.credentialOffer instanceof CredentialOffer
          ? options.credentialOffer.handle
          : pushToArray(CredentialOffer.fromJson(options.credentialOffer).handle, objectHandles)

      createReturnObj = anoncreds.createCredentialRequest({
        entropy: options.entropy,
        proverDid: options.proverDid,
        credentialDefinition,
        linkSecret: options.linkSecret,
        linkSecretId: options.linkSecretId,
        credentialOffer,
      })
    } finally {
      objectHandles.forEach((handle) => handle.clear())
    }
    return {
      credentialRequest: new CredentialRequest(createReturnObj.credentialRequest.handle),
      credentialRequestMetadata: new CredentialRequestMetadata(createReturnObj.credentialRequestMetadata.handle),
    }
  }

  public static fromJson(json: JsonObject) {
    return new CredentialRequest(anoncreds.credentialRequestFromJson({ json: JSON.stringify(json) }).handle)
  }
}
