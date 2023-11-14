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

export type NativeNonRevokedIntervalOverride = {
  revocationRegistryDefinitionId: string
  requestedFromTimestamp: number
  overrideRevocationStatusListTimestamp: number
}

export type NativeRevocationEntry = {
  revocationRegistryDefinitionEntryIndex: number
  entry: ObjectHandle
  timestamp: number
}

export type NativeCredentialRevocationConfig = {
  revocationRegistryDefinition: ObjectHandle
  revocationRegistryDefinitionPrivate: ObjectHandle
  revocationStatusList: ObjectHandle
  registryIndex: number
}

export type Anoncreds = {
  version(): string

  getCurrentError(): string
  setDefaultLogger(): void

  generateNonce(): string

  createSchema(options: { name: string; version: string; issuerId: string; attributeNames: string[] }): ObjectHandle

  createCredentialDefinition(options: {
    schemaId: string
    schema: ObjectHandle
    tag: string
    issuerId: string
    signatureType: string
    supportRevocation: boolean
  }): {
    credentialDefinition: ObjectHandle
    credentialDefinitionPrivate: ObjectHandle
    keyCorrectnessProof: ObjectHandle
  }

  createCredential(options: {
    credentialDefinition: ObjectHandle
    credentialDefinitionPrivate: ObjectHandle
    credentialOffer: ObjectHandle
    credentialRequest: ObjectHandle
    attributeRawValues: Record<string, string>
    attributeEncodedValues?: Record<string, string>
    revocationConfiguration?: NativeCredentialRevocationConfig
  }): ObjectHandle

  encodeCredentialAttributes(options: { attributeRawValues: string[] }): string[]

  processCredential(options: {
    credential: ObjectHandle
    credentialRequestMetadata: ObjectHandle
    linkSecret: string
    credentialDefinition: ObjectHandle
    revocationRegistryDefinition?: ObjectHandle
  }): ObjectHandle

  createCredentialOffer(options: {
    schemaId: string
    credentialDefinitionId: string
    keyCorrectnessProof: ObjectHandle
  }): ObjectHandle

  createCredentialRequest(options: {
    entropy?: string
    proverDid?: string
    credentialDefinition: ObjectHandle
    linkSecret: string
    linkSecretId: string
    credentialOffer: ObjectHandle
  }): { credentialRequest: ObjectHandle; credentialRequestMetadata: ObjectHandle }

  createLinkSecret(): string

  createPresentation(options: {
    presentationRequest: ObjectHandle
    credentials: NativeCredentialEntry[]
    credentialsProve: NativeCredentialProve[]
    selfAttest: Record<string, string>
    linkSecret: string
    schemas: Record<string, ObjectHandle>
    credentialDefinitions: Record<string, ObjectHandle>
  }): ObjectHandle

  verifyPresentation(options: {
    presentation: ObjectHandle
    presentationRequest: ObjectHandle
    schemas: ObjectHandle[]
    schemaIds: string[]
    credentialDefinitions: ObjectHandle[]
    credentialDefinitionIds: string[]
    revocationRegistryDefinitions?: ObjectHandle[]
    revocationRegistryDefinitionIds?: string[]
    revocationStatusLists?: ObjectHandle[]
    nonRevokedIntervalOverrides?: NativeNonRevokedIntervalOverride[]
  }): boolean

  createRevocationRegistryDefinition(options: {
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
    oldRevocationState?: ObjectHandle
    oldRevocationStatusList?: ObjectHandle
  }): ObjectHandle

  createRevocationStatusList(options: {
    credentialDefinition: ObjectHandle
    revocationRegistryDefinitionId: string
    revocationRegistryDefinition: ObjectHandle
    revocationRegistryDefinitionPrivate: ObjectHandle
    issuerId: string
    issuanceByDefault: boolean
    timestamp?: number
  }): ObjectHandle

  updateRevocationStatusListTimestampOnly(options: {
    timestamp: number
    currentRevocationStatusList: ObjectHandle
  }): ObjectHandle

  updateRevocationStatusList(options: {
    credentialDefinition: ObjectHandle
    revocationRegistryDefinition: ObjectHandle
    revocationRegistryDefinitionPrivate: ObjectHandle
    currentRevocationStatusList: ObjectHandle
    issued?: number[]
    revoked?: number[]
    timestamp?: number
  }): ObjectHandle

  credentialGetAttribute(options: { objectHandle: ObjectHandle; name: string }): string

  revocationRegistryDefinitionGetAttribute(options: { objectHandle: ObjectHandle; name: string }): string

  presentationRequestFromJson(options: { json: string }): ObjectHandle

  revocationRegistryDefinitionFromJson(options: { json: string }): ObjectHandle

  revocationRegistryFromJson(options: { json: string }): ObjectHandle

  revocationStatusListFromJson(options: { json: string }): ObjectHandle

  presentationFromJson(options: { json: string }): ObjectHandle

  credentialOfferFromJson(options: { json: string }): ObjectHandle

  schemaFromJson(options: { json: string }): ObjectHandle

  credentialRequestFromJson(options: { json: string }): ObjectHandle

  credentialRequestMetadataFromJson(options: { json: string }): ObjectHandle

  credentialFromJson(options: { json: string }): ObjectHandle

  revocationRegistryDefinitionPrivateFromJson(options: { json: string }): ObjectHandle

  revocationStateFromJson(options: { json: string }): ObjectHandle

  credentialDefinitionFromJson(options: { json: string }): ObjectHandle

  credentialDefinitionPrivateFromJson(options: { json: string }): ObjectHandle

  keyCorrectnessProofFromJson(options: { json: string }): ObjectHandle

  getJson(options: { objectHandle: ObjectHandle }): string

  getTypeName(options: { objectHandle: ObjectHandle }): string

  objectFree(options: { objectHandle: ObjectHandle }): void

  createW3CCredentialOffer(options: {
    schemaId: string
    credentialDefinitionId: string
    keyCorrectnessProof: ObjectHandle
  }): ObjectHandle

  createW3CCredentialRequest(options: {
    entropy?: string
    proverDid?: string
    credentialDefinition: ObjectHandle
    linkSecret: string
    linkSecretId: string
    credentialOffer: ObjectHandle
  }): { credentialRequest: ObjectHandle; credentialRequestMetadata: ObjectHandle }

  createW3CCredential(options: {
    credentialDefinition: ObjectHandle
    credentialDefinitionPrivate: ObjectHandle
    credentialOffer: ObjectHandle
    credentialRequest: ObjectHandle
    attributeRawValues: Record<string, string>
    revocationConfiguration?: NativeCredentialRevocationConfig
    encoding?: string
  }): ObjectHandle

  processW3CCredential(options: {
    credential: ObjectHandle
    credentialRequestMetadata: ObjectHandle
    linkSecret: string
    credentialDefinition: ObjectHandle
    revocationRegistryDefinition?: ObjectHandle
  }): ObjectHandle

  createW3CPresentation(options: {
    presentationRequest: ObjectHandle
    credentials: NativeCredentialEntry[]
    credentialsProve: NativeCredentialProve[]
    linkSecret: string
    schemas: Record<string, ObjectHandle>
    credentialDefinitions: Record<string, ObjectHandle>
  }): ObjectHandle

  verifyW3CPresentation(options: {
    presentation: ObjectHandle
    presentationRequest: ObjectHandle
    schemas: ObjectHandle[]
    schemaIds: string[]
    credentialDefinitions: ObjectHandle[]
    credentialDefinitionIds: string[]
    revocationRegistryDefinitions?: ObjectHandle[]
    revocationRegistryDefinitionIds?: string[]
    revocationStatusLists?: ObjectHandle[]
    nonRevokedIntervalOverrides?: NativeNonRevokedIntervalOverride[]
  }): boolean

  w3cPresentationFromJson(options: { json: string }): ObjectHandle

  w3cCredentialAddNonAnonCredsIntegrityProof(options: { objectHandle: ObjectHandle; proof: string }): ObjectHandle

  w3cCredentialSetId(options: { objectHandle: ObjectHandle; id: string }): ObjectHandle

  w3cCredentialSetSubjectId(options: { objectHandle: ObjectHandle; id: string }): ObjectHandle

  w3cCredentialAddContext(options: { objectHandle: ObjectHandle; context: string }): ObjectHandle

  w3cCredentialAddType(options: { objectHandle: ObjectHandle; type_: string }): ObjectHandle

  w3cCredentialGetAttribute(options: { objectHandle: ObjectHandle; name: string }): string

  w3cCredentialOfferFromJson(options: { json: string }): ObjectHandle

  w3cCredentialRequestFromJson(options: { json: string }): ObjectHandle

  w3cCredentialFromJson(options: { json: string }): ObjectHandle

  credentialToW3C(options: { objectHandle: ObjectHandle }): ObjectHandle

  credentialFromW3C(options: { objectHandle: ObjectHandle }): ObjectHandle
}
