import type { CredentialRevocationConfig } from './CredentialRevocationConfig'
import type { RevocationStatusList } from './RevocationStatusList'
import type { ObjectHandle } from '../ObjectHandle'
import type { JsonObject } from '../types'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

import { Credential } from './Credential'
import { CredentialDefinition } from './CredentialDefinition'
import { CredentialDefinitionPrivate } from './CredentialDefinitionPrivate'
import { CredentialRequestMetadata } from './CredentialRequestMetadata'
import { RevocationRegistryDefinition } from './RevocationRegistryDefinition'
import { W3CCredentialOffer } from './W3CCredentialOffer'
import { W3CCredentialRequest } from './W3CCredentialRequest'
import { pushToArray } from './utils'

export type CreateW3CCredentialOptions = {
  credentialDefinition: CredentialDefinition | JsonObject
  credentialDefinitionPrivate: CredentialDefinitionPrivate | JsonObject
  credentialOffer: W3CCredentialOffer | JsonObject
  credentialRequest: W3CCredentialRequest | JsonObject
  attributeRawValues: Record<string, string>
  revocationRegistryId?: string
  revocationConfiguration?: CredentialRevocationConfig
  revocationStatusList?: RevocationStatusList | JsonObject
  encoding?: string
}

export type ProcessW3CCredentialOptions = {
  credentialRequestMetadata: CredentialRequestMetadata | JsonObject
  linkSecret: string
  credentialDefinition: CredentialDefinition | JsonObject
  revocationRegistryDefinition?: RevocationRegistryDefinition | JsonObject
}

export type W3CCredentialFromLegacyOptions = {
  credential: Credential
  credentialDefinition: CredentialDefinition | JsonObject
}

export class W3CCredential extends AnoncredsObject {
  public static create(options: CreateW3CCredentialOptions) {
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
        options.credentialOffer instanceof W3CCredentialOffer
          ? options.credentialOffer.handle
          : pushToArray(W3CCredentialOffer.fromJson(options.credentialOffer).handle, objectHandles)

      const credentialRequest =
        options.credentialRequest instanceof W3CCredentialRequest
          ? options.credentialRequest.handle
          : pushToArray(W3CCredentialRequest.fromJson(options.credentialRequest).handle, objectHandles)

      credential = anoncreds.createW3CCredential({
        credentialDefinition,
        credentialDefinitionPrivate,
        credentialOffer,
        credentialRequest,
        attributeRawValues: options.attributeRawValues,
        revocationConfiguration: options.revocationConfiguration?.native,
        encoding: options.encoding
      })
    } finally {
      objectHandles.forEach((handle) => {
        handle.clear()
      })
    }
    return new W3CCredential(credential.handle)
  }

  public static fromJson(json: JsonObject) {
    return new W3CCredential(anoncreds.credentialFromJson({ json: JSON.stringify(json) }).handle)
  }

  public process(options: ProcessW3CCredentialOptions) {
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

      credential = anoncreds.processW3CCredential({
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
    return anoncreds.w3cCredentialGetAttribute({ objectHandle: this.handle, name: 'schema_id' })
  }

  public get credentialDefinitionId() {
    return anoncreds.w3cCredentialGetAttribute({ objectHandle: this.handle, name: 'cred_def_id' })
  }

  public get revocationRegistryId() {
    return anoncreds.w3cCredentialGetAttribute({ objectHandle: this.handle, name: 'rev_reg_id' })
  }

  public get revocationRegistryIndex() {
    const index = anoncreds.w3cCredentialGetAttribute({ objectHandle: this.handle, name: 'rev_reg_index' })
    return index ? Number(index) : undefined
  }

  public toLegacy(): Credential {
    return new Credential(
      anoncreds.credentialFromW3C({
        objectHandle: this.handle
      }).handle
    )
  }

  public static fromLegacy(options: W3CCredentialFromLegacyOptions): W3CCredential {
    let credential
    // Objects created within this method must be freed up
    const objectHandles: ObjectHandle[] = []
    try {
      const credentialDefinition =
        options.credentialDefinition instanceof CredentialDefinition
          ? options.credentialDefinition.handle
          : pushToArray(CredentialDefinition.fromJson(options.credentialDefinition).handle, objectHandles)

      credential = new W3CCredential(
        anoncreds.credentialToW3C({
          objectHandle: options.credential.handle,
          credentialDefinition
        }).handle
      )
    } finally {
      objectHandles.forEach((handle) => {
        handle.clear()
      })
    }
    return credential
  }

  public addNonAnonCredsIntegrityProof(proof: JsonObject) {
    const credential = anoncreds.w3cCredentialAddNonAnonCredsIntegrityProof({
      objectHandle: this.handle,
      proof: JSON.stringify(proof)
    })

    this.handle.clear()
    this.handle = credential
  }

  public setId(id: string) {
    const credential = anoncreds.w3cCredentialSetId({
      objectHandle: this.handle,
      id
    })

    this.handle.clear()
    this.handle = credential
  }

  public setSubjectId(id: string) {
    const credential = anoncreds.w3cCredentialSetSubjectId({
      objectHandle: this.handle,
      id
    })

    this.handle.clear()
    this.handle = credential
  }

  public addContext(context: string) {
    const credential = anoncreds.w3cCredentialAddContext({
      objectHandle: this.handle,
      context
    })

    this.handle.clear()
    this.handle = credential
  }

  public addType(type_: string) {
    const credential = anoncreds.w3cCredentialAddType({
      objectHandle: this.handle,
      type_
    })

    this.handle.clear()
    this.handle = credential
  }
}
