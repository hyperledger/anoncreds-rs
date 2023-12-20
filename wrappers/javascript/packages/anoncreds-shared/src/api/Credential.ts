import type { CredentialRevocationConfig } from './CredentialRevocationConfig'
import type { RevocationStatusList } from './RevocationStatusList'
import type { ObjectHandle } from '../ObjectHandle'
import type { JsonObject } from '../types'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

import { CredentialDefinition } from './CredentialDefinition'
import { CredentialDefinitionPrivate } from './CredentialDefinitionPrivate'
import { CredentialOffer } from './CredentialOffer'
import { CredentialRequest } from './CredentialRequest'
import { CredentialRequestMetadata } from './CredentialRequestMetadata'
import { RevocationRegistryDefinition } from './RevocationRegistryDefinition'
import { W3cCredential } from './W3cCredential'
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

export type CredentialToW3cOptions = {
  credentialDefinition: CredentialDefinition | JsonObject
  version?: string
}

export type CredentialFromW3cOptions = {
  credential: W3cCredential
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

      credential = anoncreds.createCredential({
        credentialDefinition,
        credentialDefinitionPrivate,
        credentialOffer,
        credentialRequest,
        attributeRawValues: options.attributeRawValues,
        attributeEncodedValues: options.attributeEncodedValues,
        revocationConfiguration: options.revocationConfiguration?.native
      })
    } finally {
      objectHandles.forEach((handle) => {
        handle.clear()
      })
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
        revocationRegistryDefinition
      })

      // We can discard previous handle and store the new one
      this.handle.clear()
      this.handle = credential
    } finally {
      objectHandles.forEach((handle) => {
        handle.clear()
      })
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

  public toW3c(options: CredentialToW3cOptions): W3cCredential {
    let credential
    // Objects created within this method must be freed up
    const objectHandles: ObjectHandle[] = []
    try {
      const credentialDefinition =
        options.credentialDefinition instanceof CredentialDefinition
          ? options.credentialDefinition.handle
          : pushToArray(CredentialDefinition.fromJson(options.credentialDefinition).handle, objectHandles)

      credential = new W3cCredential(
        anoncreds.credentialToW3c({
          objectHandle: this.handle,
          credentialDefinition,
          version: options.version
        }).handle
      )
    } finally {
      objectHandles.forEach((handle) => {
        handle.clear()
      })
    }
    return credential
  }

  public static fromW3c(options: CredentialFromW3cOptions) {
    return new Credential(anoncreds.credentialFromW3c({ objectHandle: options.credential.handle }).handle)
  }
}
