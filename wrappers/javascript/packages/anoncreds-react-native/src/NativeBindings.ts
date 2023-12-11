import type { ReturnObject } from './serialize'
import type { NativeCredentialProve, NativeNonRevokedIntervalOverride } from '@hyperledger/anoncreds-shared'

// Alias for _Handle.handle
type Handle = number

export type NativeBindings = {
  version(options: Record<never, never>): string
  getCurrentError(options: Record<never, never>): string

  setDefaultLogger(options: Record<never, never>): ReturnObject<null>
  generateNonce(options: Record<never, never>): ReturnObject<string>
  createSchema(options: {
    name: string
    version: string
    issuerId: string
    attributeNames: string[]
  }): ReturnObject<Handle>

  createRevocationStatusList(options: {
    credentialDefinition: Handle
    revocationRegistryDefinitionId: string
    revocationRegistryDefinition: Handle
    revocationRegistryDefinitionPrivate: Handle
    issuerId: string
    timestamp?: number
    issuanceByDefault: number
  }): ReturnObject<Handle>

  updateRevocationStatusList(options: {
    credentialDefinition: Handle
    revocationRegistryDefinition: Handle
    revocationRegistryDefinitionPrivate: Handle
    currentRevocationStatusList: Handle
    issued?: number[]
    revoked?: number[]
    timestamp?: number
  }): ReturnObject<Handle>

  updateRevocationStatusListTimestampOnly(options: {
    timestamp: number
    currentRevocationStatusList: Handle
  }): ReturnObject<Handle>

  createCredentialDefinition(options: {
    schemaId: string
    schema: number
    issuerId: string
    tag: string
    signatureType: string
    supportRevocation: number
  }): ReturnObject<{ credentialDefinition: Handle; credentialDefinitionPrivate: Handle; keyCorrectnessProof: Handle }>

  createCredential(options: {
    credentialDefinition: number
    credentialDefinitionPrivate: number
    credentialOffer: number
    credentialRequest: number
    attributeNames: string[]
    attributeRawValues: string[]
    attributeEncodedValues?: string[]
    revocationConfiguration?: {
      registryIndex: number
      revocationRegistryDefinition: number
      revocationRegistryDefinitionPrivate: number
      revocationStatusList?: number
    }
  }): ReturnObject<Handle>
  encodeCredentialAttributes(options: { attributeRawValues: string[] }): ReturnObject<string>
  processCredential(options: {
    credential: number
    credentialRequestMetadata: number
    linkSecret: string
    credentialDefinition: number
    revocationRegistryDefinition?: number
  }): ReturnObject<Handle>

  createCredentialOffer(options: {
    schemaId: string
    credentialDefinitionId: string
    keyCorrectnessProof: number
  }): ReturnObject<Handle>

  createCredentialRequest(options: {
    entropy?: string
    proverDid?: string
    credentialDefinition: number
    linkSecret: string
    linkSecretId: string
    credentialOffer: number
  }): ReturnObject<{ credentialRequest: Handle; credentialRequestMetadata: Handle }>

  createLinkSecret(options: Record<never, never>): ReturnObject<string>

  createPresentation(options: {
    presentationRequest: number
    credentials: { credential: number; timestamp?: number; revocationState?: number }[]
    credentialsProve: NativeCredentialProve[]
    selfAttestNames: string[]
    selfAttestValues: string[]
    linkSecret: string
    schemaIds: string[]
    schemas: number[]
    credentialDefinitionIds: string[]
    credentialDefinitions: number[]
  }): ReturnObject<Handle>

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
  }): ReturnObject<number>

  createRevocationRegistryDefinition(options: {
    credentialDefinition: number
    credentialDefinitionId: string
    issuerId: string
    tag: string
    revocationRegistryType: string
    maximumCredentialNumber: number
    tailsDirectoryPath?: string
  }): ReturnObject<{
    registryDefinition: Handle
    registryDefinitionPrivate: Handle
    registryEntry: Handle
    registryInitDelta: Handle
  }>

  createOrUpdateRevocationState(options: {
    revocationRegistryDefinition: number
    revocationStatusList: number
    revocationRegistryIndex: number
    tailsPath: string
    oldRevocationState?: number
    oldRevocationStatusList?: number
  }): ReturnObject<Handle>

  presentationRequestFromJson(options: { json: string }): ReturnObject<Handle>

  schemaGetAttribute(options: { objectHandle: number; name: string }): ReturnObject<string>

  revocationRegistryDefinitionGetAttribute(options: { objectHandle: number; name: string }): ReturnObject<string>

  credentialGetAttribute(options: { objectHandle: number; name: string }): ReturnObject<string>

  getJson(options: { objectHandle: number }): ReturnObject<string>

  getTypeName(options: { objectHandle: number }): ReturnObject<string>

  objectFree(options: { objectHandle: number }): ReturnObject<never>

  credentialDefinitionGetAttribute(options: { objectHandle: number; name: string }): ReturnObject<string>

  revocationRegistryDefinitionFromJson(options: { json: string }): ReturnObject<Handle>

  revocationRegistryFromJson(options: { json: string }): ReturnObject<Handle>

  revocationStatusListFromJson(options: { json: string }): ReturnObject<Handle>

  presentationFromJson(options: { json: string }): ReturnObject<Handle>

  credentialOfferFromJson(options: { json: string }): ReturnObject<Handle>

  schemaFromJson(options: { json: string }): ReturnObject<Handle>

  credentialRequestFromJson(options: { json: string }): ReturnObject<Handle>

  credentialRequestMetadataFromJson(options: { json: string }): ReturnObject<Handle>

  credentialFromJson(options: { json: string }): ReturnObject<Handle>

  revocationRegistryDefinitionPrivateFromJson(options: { json: string }): ReturnObject<Handle>

  revocationStateFromJson(options: { json: string }): ReturnObject<Handle>

  credentialDefinitionFromJson(options: { json: string }): ReturnObject<Handle>

  credentialDefinitionPrivateFromJson(options: { json: string }): ReturnObject<Handle>

  keyCorrectnessProofFromJson(options: { json: string }): ReturnObject<Handle>

  createW3cCredentialOffer(options: {
    schemaId: string
    credentialDefinitionId: string
    keyCorrectnessProof: number
  }): ReturnObject<Handle>

  createW3cCredentialRequest(options: {
    entropy?: string
    proverDid?: string
    credentialDefinition: number
    linkSecret: string
    linkSecretId: string
    credentialOffer: number
  }): ReturnObject<{ credentialRequest: Handle; credentialRequestMetadata: Handle }>

  createW3cCredential(options: {
    credentialDefinition: number
    credentialDefinitionPrivate: number
    credentialOffer: number
    credentialRequest: number
    attributeNames: string[]
    attributeRawValues: string[]
    revocationConfiguration?: {
      registryIndex: number
      revocationRegistryDefinition: number
      revocationRegistryDefinitionPrivate: number
      revocationStatusList?: number
    }
    encoding?: string
  }): ReturnObject<Handle>

  processW3cCredential(options: {
    credential: number
    credentialRequestMetadata: number
    linkSecret: string
    credentialDefinition: number
    revocationRegistryDefinition?: number
  }): ReturnObject<Handle>

  w3cCredentialGetAttribute(options: { objectHandle: number; name: string }): ReturnObject<string>

  w3cCredentialAddNonAnonCredsIntegrityProof(options: { objectHandle: number; proof: string }): ReturnObject<Handle>

  w3cCredentialSetId(options: { objectHandle: number; id: string }): ReturnObject<Handle>

  w3cCredentialSetSubjectId(options: { objectHandle: number; id: string }): ReturnObject<Handle>

  w3cCredentialAddContext(options: { objectHandle: number; context: string }): ReturnObject<Handle>

  w3cCredentialAddType(options: { objectHandle: number; type: string }): ReturnObject<Handle>

  credentialToW3c(options: { objectHandle: number; credentialDefinition: number }): ReturnObject<Handle>

  credentialFromW3c(options: { objectHandle: number }): ReturnObject<Handle>

  createW3cPresentation(options: {
    presentationRequest: number
    credentials: { credential: number; timestamp?: number; revocationState?: number }[]
    credentialsProve: NativeCredentialProve[]
    linkSecret: string
    schemaIds: string[]
    schemas: number[]
    credentialDefinitionIds: string[]
    credentialDefinitions: number[]
  }): ReturnObject<Handle>

  verifyW3cPresentation(options: {
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
  }): ReturnObject<number>

  w3cCredentialOfferFromJson(options: { json: string }): ReturnObject<Handle>

  w3cCredentialRequestFromJson(options: { json: string }): ReturnObject<Handle>

  w3cCredentialFromJson(options: { json: string }): ReturnObject<Handle>

  w3cPresentationFromJson(options: { json: string }): ReturnObject<Handle>
}
