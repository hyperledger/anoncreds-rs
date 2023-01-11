import type { Schema } from './Schema'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

import { CredentialDefinitionPrivate } from './CredentialDefinitionPrivate'
import { KeyCorrectnessProof } from './KeyCorrectnessProof'

export type CreateCredentialDefinitionOptions = {
  originDid: string
  schema: Schema
  signatureType: string
  tag: string
  supportRevocation?: boolean
}

export class CredentialDefinition extends AnoncredsObject {
  public static create(options: CreateCredentialDefinitionOptions) {
    const { credentialDefinition, credentialDefinitionPrivate, keyProof } = anoncreds.createCredentialDefinition({
      originDid: options.originDid,
      schema: options.schema.handle,
      signatureType: options.signatureType,
      tag: options.tag,
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

  public getId() {
    return anoncreds.credentialDefinitionGetAttribute({ objectHandle: this.handle, name: 'id' })
  }

  public getSchemaId() {
    return anoncreds.credentialDefinitionGetAttribute({ objectHandle: this.handle, name: 'schema_id' })
  }
}
