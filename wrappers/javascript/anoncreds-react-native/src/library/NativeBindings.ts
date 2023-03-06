import type { ReturnObject } from '../utils/serialize'
import type {
  NativeCredentialEntry,
  NativeCredentialProve,
  NativeCredentialRevocationConfig,
} from '@hyperledger/anoncreds-shared'

// Alias for _Handle.handle
type Handle = number

export interface NativeBindings {
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
    revocationRegistryDefinitionId: string
    revocationRegistryDefinition: Handle
    timestamp?: number
    issuanceByDefault: number
  }): ReturnObject<Handle>

  updateRevocationStatusList(options: {
    timestamp?: number
    issued?: number[]
    revoked?: number[]
    revocationRegistryDefinition: Handle
    currentRevocationStatusList: Handle
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
    attributeRawValues: string
    attributeEncodedValues?: string
    revocationConfiguration?: NativeCredentialRevocationConfig
  }): ReturnObject<{ credential: Handle; revocationRegistry: Handle; revocationDelta: Handle }>

  encodeCredentialAttributes(options: { attributeRawValues: Array<string> }): ReturnObject<string>

  processCredential(options: {
    credential: number
    credentialRequestMetadata: number
    masterSecret: number
    credentialDefinition: number
    revocationRegistryDefinition?: number
  }): ReturnObject<Handle>

  createCredentialOffer(options: {
    schemaId: string
    credentialDefinitionId: string
    keyProof: number
  }): ReturnObject<Handle>

  createCredentialRequest(options: {
    entropy?: string
    proverDid?: string
    credentialDefinition: number
    masterSecret: number
    masterSecretId: string
    credentialOffer: number
  }): ReturnObject<{ credentialRequest: Handle; credentialRequestMetadata: Handle }>

  createMasterSecret(options: Record<never, never>): ReturnObject<number>

  createPresentation(options: {
    presentationRequest: number
    credentials: NativeCredentialEntry[]
    credentialsProve: NativeCredentialProve[]
    selfAttest: string
    masterSecret: number
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
    revocationRegistryIndex: number
    tailsPath: string
    revocationState?: number
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

  presentationFromJson(options: { json: string }): ReturnObject<Handle>

  credentialOfferFromJson(options: { json: string }): ReturnObject<Handle>

  schemaFromJson(options: { json: string }): ReturnObject<Handle>

  masterSecretFromJson(options: { json: string }): ReturnObject<Handle>

  credentialRequestFromJson(options: { json: string }): ReturnObject<Handle>

  credentialRequestMetadataFromJson(options: { json: string }): ReturnObject<Handle>

  credentialFromJson(options: { json: string }): ReturnObject<Handle>

  revocationRegistryDefinitionPrivateFromJson(options: { json: string }): ReturnObject<Handle>

  revocationRegistryDeltaFromJson(options: { json: string }): ReturnObject<Handle>

  revocationStateFromJson(options: { json: string }): ReturnObject<Handle>

  credentialDefinitionFromJson(options: { json: string }): ReturnObject<Handle>

  credentialDefinitionPrivateFromJson(options: { json: string }): ReturnObject<Handle>

  keyCorrectnessProofFromJson(options: { json: string }): ReturnObject<Handle>
}
