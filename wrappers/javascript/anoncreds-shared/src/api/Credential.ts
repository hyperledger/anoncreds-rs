import type { ObjectHandle } from '../ObjectHandle'
import type { JsonObject } from '../types'
import type { CredentialRevocationConfig } from './CredentialRevocationConfig'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

import { CredentialDefinition } from './CredentialDefinition'
import { CredentialDefinitionPrivate } from './CredentialDefinitionPrivate'
import { CredentialOffer } from './CredentialOffer'
import { CredentialRequest } from './CredentialRequest'
import { CredentialRequestMetadata } from './CredentialRequestMetadata'
import { RevocationRegistryDefinition } from './RevocationRegistryDefinition'
import { RevocationStatusList } from './RevocationStatusList'
import { pushToArray } from './utils'

export type CreateCredentialOptions = {
  credentialDefinition: CredentialDefinition | JsonObject
  credentialDefinitionPrivate: CredentialDefinitionPrivate | JsonObject
  credentialOffer: CredentialOffer | JsonObject
  credentialRequest: CredentialRequest | JsonObject
  attributeRawValues: Record<string, string>
  attributeEncodedValues?: Record<string, string>
  revocationRegistryId?: string
  revocationConfiguration?: CredentialRevocationConfig
  revocationStatusList?: RevocationStatusList | JsonObject
}

export type ProcessCredentialOptions = {
  credentialRequestMetadata: CredentialRequestMetadata | JsonObject
  linkSecret: string
  credentialDefinition: CredentialDefinition | JsonObject
  revocationRegistryDefinition?: RevocationRegistryDefinition | JsonObject
}

export class Credential extends AnoncredsObject {
  public static create(options: CreateCredentialOptions) {
    let credential
    // Objects created within this method must be freed up
    const objectHandles: ObjectHandle[] = []
    try {
      const credentialDefinition =
        options.credentialDefinition instanceof CredentialDefinition
          ? options.credentialDefinition.handle
          : pushToArray(CredentialDefinition.fromJson(options.credentialDefinition).handle, objectHandles)

      const credentialDefinitionPrivate =
        options.credentialDefinitionPrivate instanceof CredentialDefinitionPrivate
          ? options.credentialDefinitionPrivate.handle
          : pushToArray(CredentialDefinitionPrivate.fromJson(options.credentialDefinitionPrivate).handle, objectHandles)

      const credentialOffer =
        options.credentialOffer instanceof CredentialOffer
          ? options.credentialOffer.handle
          : pushToArray(CredentialOffer.fromJson(options.credentialOffer).handle, objectHandles)

      const credentialRequest =
        options.credentialRequest instanceof CredentialRequest
          ? options.credentialRequest.handle
          : pushToArray(CredentialRequest.fromJson(options.credentialRequest).handle, objectHandles)

      const revocationStatusList =
        options.revocationStatusList instanceof RevocationStatusList
          ? options.revocationStatusList.handle
          : options.revocationStatusList !== undefined
          ? pushToArray(RevocationStatusList.fromJson(options.revocationStatusList).handle, objectHandles)
          : undefined

      credential = anoncreds.createCredential({
        credentialDefinition,
        credentialDefinitionPrivate,
        credentialOffer,
        credentialRequest,
        attributeRawValues: options.attributeRawValues,
        attributeEncodedValues: options.attributeEncodedValues,
        revocationRegistryId: options.revocationRegistryId,
        revocationConfiguration: options.revocationConfiguration?.native,
        revocationStatusList,
      })
    } finally {
      objectHandles.forEach((handle) => handle.clear())
    }
    return new Credential(credential.handle)
  }

  public static fromJson(json: JsonObject) {
    return new Credential(anoncreds.credentialFromJson({ json: JSON.stringify(json) }).handle)
  }

  public process(options: ProcessCredentialOptions) {
    let credential
    // Objects created within this method must be freed up
    const objectHandles: ObjectHandle[] = []
    try {
      const credentialDefinition =
        options.credentialDefinition instanceof CredentialDefinition
          ? options.credentialDefinition.handle
          : pushToArray(CredentialDefinition.fromJson(options.credentialDefinition).handle, objectHandles)

      const credentialRequestMetadata =
        options.credentialRequestMetadata instanceof CredentialRequestMetadata
          ? options.credentialRequestMetadata.handle
          : pushToArray(CredentialRequestMetadata.fromJson(options.credentialRequestMetadata).handle, objectHandles)

      const revocationRegistryDefinition =
        options.revocationRegistryDefinition instanceof RevocationRegistryDefinition
          ? options.revocationRegistryDefinition.handle
          : options.revocationRegistryDefinition !== undefined
          ? pushToArray(
              RevocationRegistryDefinition.fromJson(options.revocationRegistryDefinition).handle,
              objectHandles
            )
          : undefined

      credential = anoncreds.processCredential({
        credential: this.handle,
        credentialDefinition,
        credentialRequestMetadata,
        linkSecret: options.linkSecret,
        revocationRegistryDefinition,
      })

      // We can discard previous handle and store the new one
      this.handle.clear()
      this.handle = credential
    } finally {
      objectHandles.forEach((handle) => handle.clear())
    }
    return this
  }

  public get schemaId() {
    return anoncreds.credentialGetAttribute({ objectHandle: this.handle, name: 'schema_id' })
  }

  public get credentialDefinitionId() {
    return anoncreds.credentialGetAttribute({ objectHandle: this.handle, name: 'cred_def_id' })
  }

  public get revocationRegistryId() {
    return anoncreds.credentialGetAttribute({ objectHandle: this.handle, name: 'rev_reg_id' })
  }

  public get revocationRegistryIndex() {
    const index = anoncreds.credentialGetAttribute({ objectHandle: this.handle, name: 'rev_reg_index' })
    return index ? Number(index) : undefined
  }
}
