// Each platform, Nodejs and React Native, should implement this interface
// This will make sure that when wrapping both methods to shared functionality

import type { ObjectHandle } from './ObjectHandle'

export type NativeCredentialEntry = {
  credential: ObjectHandle
  timestamp?: number
  revocationState?: ObjectHandle
}

export type NativeCredentialProve = {
  entryIndex: number
  referent: string
  isPredicate: boolean
  reveal: boolean
}

export type NativeRevocationEntry = {
  revocationRegistryDefinitionEntryIndex: number
  entry: ObjectHandle
  timestamp: number
}

export type NativeCredentialRevocationConfig = {
  revocationRegistryDefinition: ObjectHandle
  revocationRegistryDefinitionPrivate: ObjectHandle
  registryIndex: number
  tailsPath: string
}

export interface Anoncreds {
  version(): string

  getCurrentError(): string

  generateNonce(): string

  createSchema(options: { name: string; version: string; issuerId: string; attributeNames: string[] }): ObjectHandle

  createCredentialDefinition(options: {
    schemaId: string
    schema: ObjectHandle
    tag: string
    issuerId: string
    signatureType: string
    supportRevocation: boolean
  }): { credentialDefinition: ObjectHandle; credentialDefinitionPrivate: ObjectHandle; keyProof: ObjectHandle }

  createCredential(options: {
    credentialDefinition: ObjectHandle
    credentialDefinitionPrivate: ObjectHandle
    credentialOffer: ObjectHandle
    credentialRequest: ObjectHandle
    attributeRawValues: Record<string, string>
    attributeEncodedValues?: Record<string, string>
    revocationRegistryId?: string
    revocationStatusList?: ObjectHandle
    revocationConfiguration?: NativeCredentialRevocationConfig
  }): ObjectHandle

  encodeCredentialAttributes(options: { attributeRawValues: Array<string> }): Array<string>

  processCredential(options: {
    credential: ObjectHandle
    credentialRequestMetadata: ObjectHandle
    masterSecret: ObjectHandle
    credentialDefinition: ObjectHandle
    revocationRegistryDefinition?: ObjectHandle
  }): ObjectHandle

  createCredentialOffer(options: {
    schemaId: string
    credentialDefinitionId: string
    keyProof: ObjectHandle
  }): ObjectHandle

  createCredentialRequest(options: {
    proverDid?: string
    credentialDefinition: ObjectHandle
    masterSecret: ObjectHandle
    masterSecretId: string
    credentialOffer: ObjectHandle
  }): { credentialRequest: ObjectHandle; credentialRequestMetadata: ObjectHandle }

  createMasterSecret(): ObjectHandle

  createPresentation(options: {
    presentationRequest: ObjectHandle
    credentials: NativeCredentialEntry[]
    credentialsProve: NativeCredentialProve[]
    selfAttest: Record<string, string>
    masterSecret: ObjectHandle
    schemas: Record<string, ObjectHandle>
    credentialDefinitions: Record<string, ObjectHandle>
  }): ObjectHandle

  verifyPresentation(options: {
    presentation: ObjectHandle
    presentationRequest: ObjectHandle
    schemas: ObjectHandle[]
    credentialDefinitions: ObjectHandle[]
    revocationRegistryDefinitions?: ObjectHandle[]
    revocationEntries?: NativeRevocationEntry[]
  }): boolean

  createRevocationRegistryDef(options: {
    credentialDefinition: ObjectHandle
    credentialDefinitionId: string
    issuerId: string
    tag: string
    revocationRegistryType: string
    maximumCredentialNumber: number
    tailsDirectoryPath?: string
  }): {
    revocationRegistryDefinition: ObjectHandle
    revocationRegistryDefinitionPrivate: ObjectHandle
  }

  createOrUpdateRevocationState(options: {
    revocationRegistryDefinition: ObjectHandle
    revocationStatusList: ObjectHandle
    revocationRegistryIndex: number
    tailsPath: string
    previousRevocationState?: ObjectHandle
  }): ObjectHandle

  createRevocationStatusList(options: {
    revocationRegistryDefinitionId: string
    revocationRegistryDefinition: ObjectHandle
    timestamp?: number
    issuanceByDefault: boolean
  }): ObjectHandle

  updateRevocationStatusListTimestampOnly(options: { timestamp: number; currentList: ObjectHandle }): ObjectHandle

  updateRevocationStatusList(options: {
    timestamp?: number
    issued?: Array<number>
    revoked?: Array<number>
    revocationRegistryDefinition: ObjectHandle
    currentList: ObjectHandle
  }): ObjectHandle

  credentialGetAttribute(options: { objectHandle: ObjectHandle; name: string }): string

  revocationRegistryDefinitionGetAttribute(options: { objectHandle: ObjectHandle; name: string }): string

  presentationRequestFromJson(options: { json: string }): ObjectHandle

  revocationRegistryDefinitionFromJson(options: { json: string }): ObjectHandle

  revocationRegistryFromJson(options: { json: string }): ObjectHandle

  presentationFromJson(options: { json: string }): ObjectHandle

  credentialOfferFromJson(options: { json: string }): ObjectHandle

  schemaFromJson(options: { json: string }): ObjectHandle

  masterSecretFromJson(options: { json: string }): ObjectHandle

  credentialRequestFromJson(options: { json: string }): ObjectHandle

  credentialRequestMetadataFromJson(options: { json: string }): ObjectHandle

  credentialFromJson(options: { json: string }): ObjectHandle

  revocationRegistryDefinitionPrivateFromJson(options: { json: string }): ObjectHandle

  revocationRegistryDeltaFromJson(options: { json: string }): ObjectHandle

  revocationStateFromJson(options: { json: string }): ObjectHandle

  credentialDefinitionFromJson(options: { json: string }): ObjectHandle

  credentialDefinitionPrivateFromJson(options: { json: string }): ObjectHandle

  keyCorrectnessProofFromJson(options: { json: string }): ObjectHandle

  getJson(options: { objectHandle: ObjectHandle }): string

  getTypeName(options: { objectHandle: ObjectHandle }): string

  objectFree(options: { objectHandle: ObjectHandle }): void
}
