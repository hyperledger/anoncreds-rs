import type {
  NativeCredentialEntry,
  NativeCredentialProve,
  NativeRevocationEntry,
  NativeCredentialRevocationConfig,
} from 'indy-credx-shared'

// Alias for _Handle.handle
type _Handle = number

export interface NativeBindings {
  version(options: Record<never, never>): string
  getCurrentError(options: Record<never, never>): string
  generateNonce(options: Record<never, never>): string
  createSchema(options: {
    originDid: string
    name: string
    version: string
    attributeNames: string[]
    sequenceNumber?: number
  }): _Handle
  createCredentialDefinition(options: {
    originDid: string
    schema: number
    tag: string
    signatureType: string
    supportRevocation: number
  }): { credentialDefinition: _Handle; credentialDefinitionPrivate: _Handle; keyProof: _Handle }
  createCredential(options: {
    credentialDefinition: number
    credentialDefinitionPrivate: number
    credentialOffer: number
    credentialRequest: number
    attributeRawValues: string
    attributeEncodedValues?: string
    revocationConfiguration?: NativeCredentialRevocationConfig
  }): { credential: _Handle; revocationRegistry: _Handle; revocationDelta: _Handle }
  encodeCredentialAttributes(options: { attributeRawValues: Array<string> }): string
  processCredential(options: {
    credential: number
    credentialRequestMetadata: number
    masterSecret: number
    credentialDefinition: number
    revocationRegistryDefinition?: number
  }): _Handle
  revokeCredential(options: {
    revocationRegistryDefinition: number
    revocationRegistry: number
    credentialRevocationIndex: number
    tailsPath: string
  }): { revocationRegistry: _Handle; revocationRegistryDelta: _Handle }

  createCredentialOffer(options: { schemaId: string; credentialDefinition: number; keyProof: number }): _Handle

  createCredentialRequest(options: {
    proverDid: string
    credentialDefinition: number
    masterSecret: number
    masterSecretId: string
    credentialOffer: number
  }): { credentialRequest: _Handle; credentialRequestMeta: _Handle }

  createMasterSecret(options: Record<never, never>): number

  createPresentation(options: {
    presentationRequest: number
    credentials: NativeCredentialEntry[]
    credentialsProve: NativeCredentialProve[]
    selfAttest: string
    masterSecret: number
    schemas: number[]
    credentialDefinitions: number[]
  }): _Handle

  verifyPresentation(options: {
    presentation: number
    presentationRequest: number
    schemas: number[]
    credentialDefinitions: number[]
    revocationRegistryDefinitions: number[]
    revocationEntries: NativeRevocationEntry[]
  }): boolean

  createRevocationRegistry(options: {
    originDid: string
    credentialDefinition: number
    tag: string
    revocationRegistryType: string
    issuanceType?: string
    maximumCredentialNumber: number
    tailsDirectoryPath?: string
  }): {
    registryDefinition: _Handle
    registryDefinitionPrivate: _Handle
    registryEntry: _Handle
    registryInitDelta: _Handle
  }

  updateRevocationRegistry(options: {
    revocationRegistryDefinition: number
    revocationRegistry: number
    issued: number[]
    revoked: number[]
    tailsDirectoryPath: string
  }): { revocationRegistry: _Handle; revocationRegistryDelta: _Handle }

  mergeRevocationRegistryDeltas(options: {
    revocationRegistryDelta1: number
    revocationRegistryDelta2: number
  }): _Handle

  createOrUpdateRevocationState(options: {
    revocationRegistryDefinition: number
    revocationRegistryDelta: number
    revocationRegistryIndex: number
    timestamp: number
    tailsPath: string
    previousRevocationState?: number
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
