import type { Schema } from './Schema'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

import { CredentialDefinitionPrivate } from './CredentialDefinitionPrivate'
import { KeyCorrectnessProof } from './KeyCorrectnessProof'

export type CreateCredentialDefinitionOptions = {
  schemaId: string
  schema: Schema
  signatureType: string
  tag: string
  issuerId: string
  supportRevocation?: boolean
}

export class CredentialDefinition extends AnoncredsObject {
  public static create(options: CreateCredentialDefinitionOptions) {
    const { credentialDefinition, credentialDefinitionPrivate, keyProof } = anoncreds.createCredentialDefinition({
      schemaId: options.schemaId,
      schema: options.schema.handle,
      signatureType: options.signatureType,
      tag: options.tag,
      issuerId: options.issuerId,
      supportRevocation: options.supportRevocation ?? false,
    })

    return {
      credentialDefinition: new CredentialDefinition(credentialDefinition.handle),
      credentialDefinitionPrivate: new CredentialDefinitionPrivate(credentialDefinitionPrivate.handle),
      keyCorrectnessProof: new KeyCorrectnessProof(keyProof.handle),
    }
  }

  public static load(json: string) {
    return new CredentialDefinition(anoncreds.credentialDefinitionFromJson({ json }).handle)
  }
}
