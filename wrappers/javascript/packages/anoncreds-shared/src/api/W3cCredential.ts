import type { CredentialRevocationConfig } from './CredentialRevocationConfig'
import type { RevocationStatusList } from './RevocationStatusList'
import type { ObjectHandle } from '../ObjectHandle'
import type { JsonObject } from '../types'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

import { Credential } from './Credential'
import { CredentialDefinition } from './CredentialDefinition'
import { CredentialDefinitionPrivate } from './CredentialDefinitionPrivate'
import { CredentialOffer } from './CredentialOffer'
import { CredentialRequest } from './CredentialRequest'
import { CredentialRequestMetadata } from './CredentialRequestMetadata'
import { RevocationRegistryDefinition } from './RevocationRegistryDefinition'
import { pushToArray } from './utils'

export type CreateW3cCredentialOptions = {
  credentialDefinition: CredentialDefinition | JsonObject
  credentialDefinitionPrivate: CredentialDefinitionPrivate | JsonObject
  credentialOffer: CredentialOffer | JsonObject
  credentialRequest: CredentialRequest | JsonObject
  attributeRawValues: Record<string, string>
  revocationRegistryId?: string
  revocationConfiguration?: CredentialRevocationConfig
  revocationStatusList?: RevocationStatusList | JsonObject
  w3cVersion?: string
}

export type ProcessW3cCredentialOptions = {
  credentialRequestMetadata: CredentialRequestMetadata | JsonObject
  linkSecret: string
  credentialDefinition: CredentialDefinition | JsonObject
  revocationRegistryDefinition?: RevocationRegistryDefinition | JsonObject
}

export type W3cCredentialFromLegacyOptions = {
  credential: Credential
  issuerId: string
  w3cVersion?: string
}

export class W3cCredential extends AnoncredsObject {
  private proofDetails?: ObjectHandle

  public static create(options: CreateW3cCredentialOptions) {
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

      credential = anoncreds.createW3cCredential({
        credentialDefinition,
        credentialDefinitionPrivate,
        credentialOffer,
        credentialRequest,
        attributeRawValues: options.attributeRawValues,
        revocationConfiguration: options.revocationConfiguration?.native,
        w3cVersion: options.w3cVersion
      })
    } finally {
      objectHandles.forEach((handle) => {
        handle.clear()
      })
    }
    return new W3cCredential(credential.handle)
  }

  public static fromJson(json: JsonObject) {
    return new W3cCredential(anoncreds.w3cCredentialFromJson({ json: JSON.stringify(json) }).handle)
  }

  public process(options: ProcessW3cCredentialOptions) {
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

      credential = anoncreds.processW3cCredential({
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

  private getProofDetails(): ObjectHandle {
    if (!this.proofDetails) {
      this.proofDetails = anoncreds.w3cCredentialGetIntegrityProofDetails({ objectHandle: this.handle })
    }
    return this.proofDetails
  }

  public get schemaId() {
    const proofDetails = this.getProofDetails()
    return anoncreds.w3cCredentialProofGetAttribute({ objectHandle: proofDetails, name: 'schema_id' })
  }

  public get credentialDefinitionId() {
    const proofDetails = this.getProofDetails()
    return anoncreds.w3cCredentialProofGetAttribute({ objectHandle: proofDetails, name: 'cred_def_id' })
  }

  public get revocationRegistryId() {
    const proofDetails = this.getProofDetails()
    return anoncreds.w3cCredentialProofGetAttribute({ objectHandle: proofDetails, name: 'rev_reg_id' })
  }

  public get revocationRegistryIndex() {
    const proofDetails = this.getProofDetails()
    const index = anoncreds.w3cCredentialProofGetAttribute({ objectHandle: proofDetails, name: 'rev_reg_index' })
    return index ? Number(index) : undefined
  }

  public get timestamp() {
    const proofDetails = this.getProofDetails()
    const index = anoncreds.w3cCredentialProofGetAttribute({ objectHandle: proofDetails, name: 'timestamp' })
    return index ? Number(index) : undefined
  }

  public toLegacy(): Credential {
    return new Credential(
      anoncreds.credentialFromW3c({
        objectHandle: this.handle
      }).handle
    )
  }

  public static fromLegacy(options: W3cCredentialFromLegacyOptions): W3cCredential {
    return new W3cCredential(
      anoncreds.credentialToW3c({
        objectHandle: options.credential.handle,
        issuerId: options.issuerId,
        w3cVersion: options.w3cVersion
      }).handle
    )
  }
}
