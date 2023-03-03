import type { ObjectHandle } from '../ObjectHandle'
import type { JsonObject } from '../types'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

import { CredentialDefinition } from './CredentialDefinition'
import { CredentialOffer } from './CredentialOffer'
import { CredentialRequestMetadata } from './CredentialRequestMetadata'
import { MasterSecret } from './MasterSecret'
import { pushToArray } from './utils'

export type CreateCredentialRequestOptions = {
  proverDid?: string
  credentialDefinition: CredentialDefinition | JsonObject
  masterSecret: MasterSecret | JsonObject
  masterSecretId: string
  credentialOffer: CredentialOffer | JsonObject
}

export class CredentialRequest extends AnoncredsObject {
  public static create(options: CreateCredentialRequestOptions) {
    const objectHandles: ObjectHandle[] = []
    try {
      const credentialDefinition =
        options.credentialDefinition instanceof CredentialDefinition
          ? options.credentialDefinition.handle
          : pushToArray(CredentialDefinition.fromJson(options.credentialDefinition).handle, objectHandles)

      const masterSecret =
        options.masterSecret instanceof MasterSecret
          ? options.masterSecret.handle
          : pushToArray(MasterSecret.fromJson(options.masterSecret).handle, objectHandles)

      const credentialOffer =
        options.credentialOffer instanceof CredentialOffer
          ? options.credentialOffer.handle
          : pushToArray(CredentialOffer.fromJson(options.credentialOffer).handle, objectHandles)

      const { credentialRequest, credentialRequestMetadata } = anoncreds.createCredentialRequest({
        proverDid: options.proverDid,
        credentialDefinition,
        masterSecret,
        masterSecretId: options.masterSecretId,
        credentialOffer,
      })

      return {
        credentialRequest: new CredentialRequest(credentialRequest.handle),
        credentialRequestMetadata: new CredentialRequestMetadata(credentialRequestMetadata.handle),
      }
    } finally {
      objectHandles.forEach((handle) => handle.clear())
    }
  }

  public static fromJson(json: JsonObject) {
    return new CredentialRequest(anoncreds.credentialRequestFromJson({ json: JSON.stringify(json) }).handle)
  }
}
