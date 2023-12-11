import type { ObjectHandle } from '../ObjectHandle'
import type { JsonObject } from '../types'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

import { CredentialDefinition } from './CredentialDefinition'
import { CredentialRequestMetadata } from './CredentialRequestMetadata'
import { W3cCredentialOffer } from './W3cCredentialOffer'
import { pushToArray } from './utils'

export type CreateW3cCredentialRequestOptions = {
  entropy?: string
  proverDid?: string
  credentialDefinition: CredentialDefinition | JsonObject
  linkSecret: string
  linkSecretId: string
  credentialOffer: W3cCredentialOffer | JsonObject
}

export class W3cCredentialRequest extends AnoncredsObject {
  public static create(options: CreateW3cCredentialRequestOptions) {
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
        options.credentialOffer instanceof W3cCredentialOffer
          ? options.credentialOffer.handle
          : pushToArray(W3cCredentialOffer.fromJson(options.credentialOffer).handle, objectHandles)

      createReturnObj = anoncreds.createW3cCredentialRequest({
        entropy: options.entropy,
        proverDid: options.proverDid,
        credentialDefinition,
        linkSecret: options.linkSecret,
        linkSecretId: options.linkSecretId,
        credentialOffer
      })
    } finally {
      objectHandles.forEach((handle) => {
        handle.clear()
      })
    }
    return {
      credentialRequest: new W3cCredentialRequest(createReturnObj.credentialRequest.handle),
      credentialRequestMetadata: new CredentialRequestMetadata(createReturnObj.credentialRequestMetadata.handle)
    }
  }

  public static fromJson(json: JsonObject) {
    return new W3cCredentialRequest(anoncreds.w3cCredentialRequestFromJson({ json: JSON.stringify(json) }).handle)
  }
}
