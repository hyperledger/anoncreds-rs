import type { CredentialDefinition } from './CredentialDefinition'
import type { KeyCorrectnessProof } from './KeyCorrectnessProof'

import { IndyObject } from '../IndyObject'
import { indyCredx } from '../register'

export type CreateCredentialOfferOptions = {
  schemaId: string
  credentialDefinition: CredentialDefinition
  keyCorrectnessProof: KeyCorrectnessProof
}
export class CredentialOffer extends IndyObject {
  public static create(options: CreateCredentialOfferOptions) {
    return new CredentialOffer(
      indyCredx.createCredentialOffer({
        schemaId: options.schemaId,
        credentialDefinition: options.credentialDefinition.handle,
        keyProof: options.keyCorrectnessProof.handle,
      }).handle
    )
  }

  public static load(json: string) {
    return new CredentialOffer(indyCredx.credentialOfferFromJson({ json }).handle)
  }
}
