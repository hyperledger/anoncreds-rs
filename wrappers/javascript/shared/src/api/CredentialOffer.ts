import type { CredentialDefinition } from './CredentialDefinition'
import type { KeyCorrectnessProof } from './KeyCorrectnessProof'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

export type CreateCredentialOfferOptions = {
  schemaId: string
  credentialDefinition: CredentialDefinition
  keyCorrectnessProof: KeyCorrectnessProof
}
export class CredentialOffer extends AnoncredsObject {
  public static create(options: CreateCredentialOfferOptions) {
    return new CredentialOffer(
      anoncreds.createCredentialOffer({
        schemaId: options.schemaId,
        credentialDefinition: options.credentialDefinition.handle,
        keyProof: options.keyCorrectnessProof.handle,
      }).handle
    )
  }

  public static load(json: string) {
    return new CredentialOffer(anoncreds.credentialOfferFromJson({ json }).handle)
  }
}
