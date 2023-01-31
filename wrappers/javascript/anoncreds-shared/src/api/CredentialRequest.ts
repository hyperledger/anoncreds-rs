import type { CredentialDefinition } from './CredentialDefinition'
import type { CredentialOffer } from './CredentialOffer'
import type { MasterSecret } from './MasterSecret'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

import { CredentialRequestMetadata } from './CredentialRequestMetadata'

export type CreateCredentialRequestOptions = {
  proverDid?: string
  credentialDefinition: CredentialDefinition
  masterSecret: MasterSecret
  masterSecretId: string
  credentialOffer: CredentialOffer
}

export class CredentialRequest extends AnoncredsObject {
  public static create(options: CreateCredentialRequestOptions) {
    const { credentialRequest, credentialRequestMetadata } = anoncreds.createCredentialRequest({
      proverDid: options.proverDid,
      credentialDefinition: options.credentialDefinition.handle,
      masterSecret: options.masterSecret.handle,
      masterSecretId: options.masterSecretId,
      credentialOffer: options.credentialOffer.handle,
    })

    return {
      credentialRequest: new CredentialRequest(credentialRequest.handle),
      credentialRequestMetadata: new CredentialRequestMetadata(credentialRequestMetadata.handle),
    }
  }

  public static load(json: string) {
    return new CredentialRequest(anoncreds.credentialRequestFromJson({ json }).handle)
  }
}
