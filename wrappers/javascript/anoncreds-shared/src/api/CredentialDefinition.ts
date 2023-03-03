import type { ObjectHandle } from '../ObjectHandle'
import type { JsonObject } from '../types'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

import { CredentialDefinitionPrivate } from './CredentialDefinitionPrivate'
import { KeyCorrectnessProof } from './KeyCorrectnessProof'
import { Schema } from './Schema'
import { pushToArray } from './utils'

export type CreateCredentialDefinitionOptions = {
  schemaId: string
  schema: Schema | JsonObject
  signatureType: string
  tag: string
  issuerId: string
  supportRevocation?: boolean
}

export class CredentialDefinition extends AnoncredsObject {
  public static create(options: CreateCredentialDefinitionOptions) {
    const objectHandles: ObjectHandle[] = []
    try {
      const schema =
        options.schema instanceof Schema
          ? options.schema.handle
          : pushToArray(Schema.fromJson(options.schema).handle, objectHandles)
      const { credentialDefinition, credentialDefinitionPrivate, keyCorrectnessProof } =
        anoncreds.createCredentialDefinition({
          schemaId: options.schemaId,
          schema,
          signatureType: options.signatureType,
          tag: options.tag,
          issuerId: options.issuerId,
          supportRevocation: options.supportRevocation ?? false,
        })
      return {
        credentialDefinition: new CredentialDefinition(credentialDefinition.handle),
        credentialDefinitionPrivate: new CredentialDefinitionPrivate(credentialDefinitionPrivate.handle),
        keyCorrectnessProof: new KeyCorrectnessProof(keyCorrectnessProof.handle),
      }
    } finally {
      objectHandles.forEach((handle) => handle.clear())
    }
  }

  public static fromJson(json: JsonObject) {
    return new CredentialDefinition(anoncreds.credentialDefinitionFromJson({ json: JSON.stringify(json) }).handle)
  }
}
