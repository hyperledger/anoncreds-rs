import type { NativeCredentialProve, NativeNonRevokedIntervalOverride } from '@hyperledger/anoncreds-shared'

// Alias for _Handle.handle
type _Handle = number

export interface NativeBindings {
  version(options: Record<never, never>): string
  getCurrentError(options: Record<never, never>): string
  generateNonce(options: Record<never, never>): string
  createSchema(options: { name: string; version: string; issuerId: string; attributeNames: string[] }): _Handle
  createRevocationStatusList(options: {
    revocationRegistryDefinitionId: string
    revocationRegistryDefinition: _Handle
    issuerId: string
    timestamp?: number
    issuanceByDefault: number
  }): _Handle
  updateRevocationStatusList(options: {
    timestamp?: number
    issued?: number[]
    revoked?: number[]
    revocationRegistryDefinition: _Handle
    currentRevocationStatusList: _Handle
  }): _Handle
  updateRevocationStatusListTimestampOnly(options: { timestamp: number; currentRevocationStatusList: _Handle }): _Handle
  createCredentialDefinition(options: {
    schemaId: string
    schema: number
    issuerId: string
    tag: string
    signatureType: string
    supportRevocation: number
  }): { credentialDefinition: _Handle; credentialDefinitionPrivate: _Handle; keyCorrectnessProof: _Handle }
  createCredential(options: {
    credentialDefinition: number
    credentialDefinitionPrivate: number
    credentialOffer: number
    credentialRequest: number
    attributeNames: string[]
    attributeRawValues: string[]
    attributeEncodedValues?: string[]
    revocationRegistryId?: string
    revocationStatusList?: number
    revocationConfiguration?: {
      registryIndex: number
      revocationRegistryDefinition: number
      revocationRegistryDefinitionPrivate: number
      tailsPath: string
    }
  }): _Handle
  encodeCredentialAttributes(options: { attributeRawValues: Array<string> }): string
  processCredential(options: {
    credential: number
    credentialRequestMetadata: number
    masterSecret: number
    credentialDefinition: number
    revocationRegistryDefinition?: number
  }): _Handle
  createCredentialOffer(options: {
    schemaId: string
    credentialDefinitionId: string
    keyCorrectnessProof: number
  }): _Handle
  createCredentialRequest(options: {
    entropy?: string
    proverDid?: string
    credentialDefinition: number
    masterSecret: number
    masterSecretId: string
    credentialOffer: number
  }): { credentialRequest: _Handle; credentialRequestMetadata: _Handle }
  createMasterSecret(options: Record<never, never>): number
  createPresentation(options: {
    presentationRequest: number
    credentials: { credential: number; timestamp?: number; revocationState?: number }[]
    credentialsProve: NativeCredentialProve[]
    selfAttestNames: string[]
    selfAttestValues: string[]
    masterSecret: number
    schemaIds: string[]
    schemas: number[]
    credentialDefinitionIds: string[]
    credentialDefinitions: number[]
  }): _Handle
  verifyPresentation(options: {
    presentation: number
    presentationRequest: number
    schemas: number[]
    schemaIds: string[]
    credentialDefinitions: number[]
    credentialDefinitionIds: string[]
    revocationRegistryDefinitions?: number[]
    revocationRegistryDefinitionIds?: string[]
    revocationStatusLists?: number[]
    nonRevokedIntervalOverrides?: NativeNonRevokedIntervalOverride[]
  }): boolean
  createRevocationRegistryDefinition(options: {
    credentialDefinition: number
    credentialDefinitionId: string
    issuerId: string
    tag: string
    revocationRegistryType: string
    maximumCredentialNumber: number
    tailsDirectoryPath?: string
  }): {
    registryDefinition: _Handle
    registryDefinitionPrivate: _Handle
    registryEntry: _Handle
    registryInitDelta: _Handle
  }
  createOrUpdateRevocationState(options: {
    revocationRegistryDefinition: number
    revocationRegistryIndex: number
    tailsPath: string
    revocationState?: number
    oldRevocationStatusList?: number
  }): _Handle
  presentationRequestFromJson(options: { json: string }): _Handle
  schemaGetAttribute(options: { objectHandle: number; name: string }): string
  revocationRegistryDefinitionGetAttribute(options: { objectHandle: number; name: string }): string
  credentialGetAttribute(options: { objectHandle: number; name: string }): string
  getJson(options: { objectHandle: number }): string
  getTypeName(options: { objectHandle: number }): string
  objectFree(options: { objectHandle: number }): void
  credentialDefinitionGetAttribute(options: { objectHandle: number; name: string }): string
  revocationRegistryDefinitionFromJson(options: { json: string }): _Handle
  revocationRegistryFromJson(options: { json: string }): _Handle
  presentationFromJson(options: { json: string }): _Handle
  credentialOfferFromJson(options: { json: string }): _Handle
  schemaFromJson(options: { json: string }): _Handle
  masterSecretFromJson(options: { json: string }): _Handle
  credentialRequestFromJson(options: { json: string }): _Handle
  credentialRequestMetadataFromJson(options: { json: string }): _Handle
  credentialFromJson(options: { json: string }): _Handle
  revocationRegistryDefinitionPrivateFromJson(options: { json: string }): _Handle
  revocationRegistryDeltaFromJson(options: { json: string }): _Handle
  revocationStateFromJson(options: { json: string }): _Handle
  credentialDefinitionFromJson(options: { json: string }): _Handle
  credentialDefinitionPrivateFromJson(options: { json: string }): _Handle
  keyCorrectnessProofFromJson(options: { json: string }): _Handle
}
