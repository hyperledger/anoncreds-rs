import type {
  Anoncreds,
  NativeCredentialEntry,
  NativeCredentialProve,
  NativeCredentialRevocationConfig,
} from '@hyperledger/anoncreds-shared'

import { ObjectHandle } from '@hyperledger/anoncreds-shared'

import { anoncredsReactNative } from './library'
import { serializeArguments } from './utils'

export class ReactNativeAnoncreds implements Anoncreds {
  public createRevocationStatusList(options: {
    revocationRegistryDefinitionId: string
    revocationRegistryDefinition: ObjectHandle
    timestamp?: number
    issuanceByDefault: boolean
  }): ObjectHandle {
    const handle = anoncredsReactNative.createRevocationStatusList(serializeArguments(options))
    return new ObjectHandle(handle)
  }

  public updateRevocationStatusListTimestampOnly(options: {
    timestamp: number
    currentRevocationStatusList: ObjectHandle
  }): ObjectHandle {
    const handle = anoncredsReactNative.updateRevocationStatusListTimestampOnly(serializeArguments(options))
    return new ObjectHandle(handle)
  }

  public updateRevocationStatusList(options: {
    timestamp?: number
    issued?: number[]
    revoked?: number[]
    revocationRegistryDefinition: ObjectHandle
    currentRevocationStatusList: ObjectHandle
  }): ObjectHandle {
    const handle = anoncredsReactNative.updateRevocationStatusList(serializeArguments(options))
    return new ObjectHandle(handle)
  }

  public version(): string {
    return anoncredsReactNative.version({})
  }

  public getCurrentError(): string {
    return anoncredsReactNative.getCurrentError({})
  }

  public generateNonce(): string {
    return anoncredsReactNative.generateNonce({})
  }

  public createSchema(options: {
    name: string
    version: string
    attributeNames: string[]
    issuerId: string
  }): ObjectHandle {
    const handle = anoncredsReactNative.createSchema(serializeArguments(options))
    return new ObjectHandle(handle)
  }

  public createCredentialDefinition(options: {
    schemaId: string
    schema: ObjectHandle
    tag: string
    issuerId: string
    signatureType: string
    supportRevocation: boolean
  }): { credentialDefinition: ObjectHandle; credentialDefinitionPrivate: ObjectHandle; keyProof: ObjectHandle } {
    const { keyProof, credentialDefinition, credentialDefinitionPrivate } =
      anoncredsReactNative.createCredentialDefinition(serializeArguments(options))

    return {
      credentialDefinitionPrivate: new ObjectHandle(credentialDefinitionPrivate),
      credentialDefinition: new ObjectHandle(credentialDefinition),
      keyProof: new ObjectHandle(keyProof),
    }
  }

  public createCredential(options: {
    credentialDefinition: ObjectHandle
    credentialDefinitionPrivate: ObjectHandle
    credentialOffer: ObjectHandle
    credentialRequest: ObjectHandle
    attributeRawValues: Record<string, string>
    attributeEncodedValues?: Record<string, string>
    revocationConfiguration?: NativeCredentialRevocationConfig
  }): ObjectHandle {
    const { credential } = anoncredsReactNative.createCredential(serializeArguments(options))

    return new ObjectHandle(credential)
  }

  public encodeCredentialAttributes(options: { attributeRawValues: Array<string> }): Array<string> {
    const s = anoncredsReactNative.encodeCredentialAttributes(serializeArguments(options))
    return s.split(',')
  }

  public processCredential(options: {
    credential: ObjectHandle
    credentialRequestMetadata: ObjectHandle
    masterSecret: ObjectHandle
    credentialDefinition: ObjectHandle
    revocationRegistryDefinition?: ObjectHandle
  }): ObjectHandle {
    const handle = anoncredsReactNative.processCredential(serializeArguments(options))
    return new ObjectHandle(handle)
  }

  public createCredentialOffer(options: {
    schemaId: string
    credentialDefinitionId: string
    keyProof: ObjectHandle
  }): ObjectHandle {
    const handle = anoncredsReactNative.createCredentialOffer(serializeArguments(options))
    return new ObjectHandle(handle)
  }

  public createCredentialRequest(options: {
    proverDid?: string
    credentialDefinition: ObjectHandle
    masterSecret: ObjectHandle
    masterSecretId: string
    credentialOffer: ObjectHandle
  }): { credentialRequest: ObjectHandle; credentialRequestMetadata: ObjectHandle } {
    const { credentialRequest, credentialRequestMetadata } = anoncredsReactNative.createCredentialRequest(
      serializeArguments(options)
    )

    return {
      credentialRequestMetadata: new ObjectHandle(credentialRequestMetadata),
      credentialRequest: new ObjectHandle(credentialRequest),
    }
  }

  public createMasterSecret(): ObjectHandle {
    const handle = anoncredsReactNative.createMasterSecret({})
    return new ObjectHandle(handle)
  }

  public createPresentation(options: {
    presentationRequest: ObjectHandle
    credentials: NativeCredentialEntry[]
    credentialsProve: NativeCredentialProve[]
    selfAttest: Record<string, string>
    masterSecret: ObjectHandle
    schemas: Record<string, ObjectHandle>
    credentialDefinitions: Record<string, ObjectHandle>
  }): ObjectHandle {
    const selfAttestNames = Object.keys(options.selfAttest)
    const selfAttestValues = Object.values(options.selfAttest)
    const schemaKeys = Object.keys(options.schemas)
    const schemaValues = Object.values(options.schemas).map((o) => o.handle)
    const credentialDefinitionKeys = Object.keys(options.credentialDefinitions)
    const credentialDefinitionValues = Object.values(options.credentialDefinitions).map((o) => o.handle)

    const credentialEntries = options.credentials.map((value) => ({
      credential: value.credential.handle,
      timestamp: value.timestamp ?? -1,
      rev_state: value.revocationState?.handle ?? 0,
    }))

    const handle = anoncredsReactNative.createPresentation({
      presentationRequest: options.presentationRequest.handle,
      masterSecret: options.masterSecret.handle,
      credentialsProve: options.credentialsProve,
      selfAttestNames,
      selfAttestValues,
      credentials: credentialEntries,
      schemas: schemaValues,
      schemaIds: schemaKeys,
      credentialDefinitions: credentialDefinitionValues,
      credentialDefinitionIds: credentialDefinitionKeys,
    })
    return new ObjectHandle(handle)
  }

  public verifyPresentation(options: {
    presentation: ObjectHandle
    presentationRequest: ObjectHandle
    schemas: ObjectHandle[]
    schemaIds: string[]
    credentialDefinitions: ObjectHandle[]
    credentialDefinitionIds: string[]
    revocationRegistryDefinitions?: ObjectHandle[]
    revocationRegistryDefinitionIds: string[]
    revocationStatusLists: ObjectHandle[]
  }): boolean {
    return anoncredsReactNative.verifyPresentation(serializeArguments(options))
  }

  public createRevocationRegistryDefinition(options: {
    credentialDefinition: ObjectHandle
    credentialDefinitionId: string
    tag: string
    revocationRegistryType: string
    issuerId: string
    maximumCredentialNumber: number
    tailsDirectoryPath?: string
  }): {
    revocationRegistryDefinition: ObjectHandle
    revocationRegistryDefinitionPrivate: ObjectHandle
  } {
    const { registryDefinition, registryDefinitionPrivate } = anoncredsReactNative.createRevocationRegistryDefinition(
      serializeArguments(options)
    )

    return {
      revocationRegistryDefinitionPrivate: new ObjectHandle(registryDefinitionPrivate),
      revocationRegistryDefinition: new ObjectHandle(registryDefinition),
    }
  }

  public createOrUpdateRevocationState(options: {
    revocationRegistryDefinition: ObjectHandle
    revocationRegistryIndex: number
    tailsPath: string
    revocationState?: number
    oldRevocationStatusList?: ObjectHandle
  }): ObjectHandle {
    const handle = anoncredsReactNative.createOrUpdateRevocationState(serializeArguments(options))
    return new ObjectHandle(handle)
  }

  public presentationRequestFromJson(options: { json: string }): ObjectHandle {
    const handle = anoncredsReactNative.presentationRequestFromJson(serializeArguments(options))
    return new ObjectHandle(handle)
  }

  public schemaGetAttribute(options: { objectHandle: ObjectHandle; name: string }): string {
    return anoncredsReactNative.schemaGetAttribute(serializeArguments(options))
  }

  public revocationRegistryDefinitionGetAttribute(options: { objectHandle: ObjectHandle; name: string }): string {
    return anoncredsReactNative.revocationRegistryDefinitionGetAttribute(serializeArguments(options))
  }

  public credentialGetAttribute(options: { objectHandle: ObjectHandle; name: string }): string {
    return anoncredsReactNative.credentialGetAttribute(serializeArguments(options))
  }

  public getJson(options: { objectHandle: ObjectHandle }): string {
    return anoncredsReactNative.getJson(serializeArguments(options))
  }

  public getTypeName(options: { objectHandle: ObjectHandle }): string {
    return anoncredsReactNative.getTypeName(serializeArguments(options))
  }

  public objectFree(options: { objectHandle: ObjectHandle }): void {
    return anoncredsReactNative.objectFree(serializeArguments(options))
  }

  public credentialDefinitionGetAttribute(options: { objectHandle: ObjectHandle; name: string }): string {
    return anoncredsReactNative.credentialDefinitionGetAttribute(serializeArguments(options))
  }

  public revocationRegistryDefinitionFromJson(options: { json: string }): ObjectHandle {
    const handle = anoncredsReactNative.revocationRegistryFromJson(serializeArguments(options))
    return new ObjectHandle(handle)
  }

  public revocationRegistryFromJson(options: { json: string }): ObjectHandle {
    const handle = anoncredsReactNative.revocationRegistryFromJson(serializeArguments(options))
    return new ObjectHandle(handle)
  }

  public presentationFromJson(options: { json: string }): ObjectHandle {
    const handle = anoncredsReactNative.presentationFromJson(serializeArguments(options))
    return new ObjectHandle(handle)
  }

  public credentialOfferFromJson(options: { json: string }): ObjectHandle {
    const handle = anoncredsReactNative.credentialOfferFromJson(serializeArguments(options))
    return new ObjectHandle(handle)
  }

  public schemaFromJson(options: { json: string }): ObjectHandle {
    const handle = anoncredsReactNative.schemaFromJson(serializeArguments(options))
    return new ObjectHandle(handle)
  }

  public masterSecretFromJson(options: { json: string }): ObjectHandle {
    const handle = anoncredsReactNative.masterSecretFromJson(serializeArguments(options))
    return new ObjectHandle(handle)
  }

  public credentialRequestFromJson(options: { json: string }): ObjectHandle {
    const handle = anoncredsReactNative.credentialRequestFromJson(serializeArguments(options))
    return new ObjectHandle(handle)
  }

  public credentialRequestMetadataFromJson(options: { json: string }): ObjectHandle {
    const handle = anoncredsReactNative.credentialRequestMetadataFromJson(serializeArguments(options))
    return new ObjectHandle(handle)
  }

  public credentialFromJson(options: { json: string }): ObjectHandle {
    const handle = anoncredsReactNative.credentialFromJson(serializeArguments(options))
    return new ObjectHandle(handle)
  }

  public revocationRegistryDefinitionPrivateFromJson(options: { json: string }): ObjectHandle {
    const handle = anoncredsReactNative.revocationRegistryDefinitionPrivateFromJson(serializeArguments(options))
    return new ObjectHandle(handle)
  }

  public revocationRegistryDeltaFromJson(options: { json: string }): ObjectHandle {
    const handle = anoncredsReactNative.revocationRegistryDeltaFromJson(serializeArguments(options))
    return new ObjectHandle(handle)
  }

  public revocationStateFromJson(options: { json: string }): ObjectHandle {
    const handle = anoncredsReactNative.revocationStateFromJson(serializeArguments(options))
    return new ObjectHandle(handle)
  }
  public credentialDefinitionFromJson(options: { json: string }): ObjectHandle {
    const handle = anoncredsReactNative.credentialDefinitionFromJson(serializeArguments(options))
    return new ObjectHandle(handle)
  }

  public credentialDefinitionPrivateFromJson(options: { json: string }): ObjectHandle {
    const handle = anoncredsReactNative.credentialDefinitionPrivateFromJson(serializeArguments(options))
    return new ObjectHandle(handle)
  }

  public keyCorrectnessProofFromJson(options: { json: string }): ObjectHandle {
    const handle = anoncredsReactNative.keyCorrectnessProofFromJson(serializeArguments(options))
    return new ObjectHandle(handle)
  }
}
