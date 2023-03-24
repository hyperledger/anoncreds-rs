import type {
  Anoncreds,
  NativeCredentialEntry,
  NativeCredentialProve,
  NativeCredentialRevocationConfig,
  NativeNonRevokedIntervalOverride,
} from '@hyperledger/anoncreds-shared'

import { ObjectHandle } from '@hyperledger/anoncreds-shared'

import { anoncredsReactNative } from './library'
import { serializeArguments } from './utils'
import { handleError } from './utils/handleError'

export class ReactNativeAnoncreds implements Anoncreds {
  public createRevocationStatusList(options: {
    revocationRegistryDefinitionId: string
    revocationRegistryDefinition: ObjectHandle
    issuerId: string
    timestamp?: number
    issuanceByDefault: boolean
  }): ObjectHandle {
    const handle = handleError(anoncredsReactNative.createRevocationStatusList(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public updateRevocationStatusListTimestampOnly(options: {
    timestamp: number
    currentRevocationStatusList: ObjectHandle
  }): ObjectHandle {
    const handle = handleError(
      anoncredsReactNative.updateRevocationStatusListTimestampOnly(serializeArguments(options))
    )
    return new ObjectHandle(handle)
  }

  public updateRevocationStatusList(options: {
    timestamp?: number
    issued?: number[]
    revoked?: number[]
    revocationRegistryDefinition: ObjectHandle
    currentRevocationStatusList: ObjectHandle
  }): ObjectHandle {
    const handle = handleError(anoncredsReactNative.updateRevocationStatusList(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public version(): string {
    return anoncredsReactNative.version({})
  }

  public setDefaultLogger(): void {
    anoncredsReactNative.setDefaultLogger({})
  }

  public getCurrentError(): string {
    return anoncredsReactNative.getCurrentError({})
  }

  public generateNonce(): string {
    return handleError(anoncredsReactNative.generateNonce({}))
  }

  public createSchema(options: {
    name: string
    version: string
    attributeNames: string[]
    issuerId: string
  }): ObjectHandle {
    const handle = handleError(anoncredsReactNative.createSchema(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public createCredentialDefinition(options: {
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
  } {
    const { keyCorrectnessProof, credentialDefinition, credentialDefinitionPrivate } = handleError(
      anoncredsReactNative.createCredentialDefinition(serializeArguments(options))
    )

    return {
      credentialDefinitionPrivate: new ObjectHandle(credentialDefinitionPrivate),
      credentialDefinition: new ObjectHandle(credentialDefinition),
      keyCorrectnessProof: new ObjectHandle(keyCorrectnessProof),
    }
  }

  public createCredential(options: {
    credentialDefinition: ObjectHandle
    credentialDefinitionPrivate: ObjectHandle
    credentialOffer: ObjectHandle
    credentialRequest: ObjectHandle
    attributeRawValues: Record<string, string>
    attributeEncodedValues?: Record<string, string>
    revocationRegistryId?: string
    revocationStatusList?: ObjectHandle
    revocationConfiguration?: NativeCredentialRevocationConfig
  }): ObjectHandle {
    const attributeNames = Object.keys(options.attributeRawValues)
    const attributeRawValues = Object.values(options.attributeRawValues)
    const attributeEncodedValues = options.attributeEncodedValues
      ? Object.values(options.attributeEncodedValues)
      : undefined

    const credential = handleError(
      anoncredsReactNative.createCredential({
        ...serializeArguments(options),
        attributeRawValues,
        attributeEncodedValues,
        attributeNames,
        revocationConfiguration: options.revocationConfiguration
          ? {
              registryIndex: options.revocationConfiguration.registryIndex,
              revocationRegistryDefinition: options.revocationConfiguration.revocationRegistryDefinition.handle,
              revocationRegistryDefinitionPrivate:
                options.revocationConfiguration.revocationRegistryDefinitionPrivate.handle,
              tailsPath: options.revocationConfiguration.tailsPath,
            }
          : undefined,
      })
    )

    return new ObjectHandle(credential)
  }

  public encodeCredentialAttributes(options: { attributeRawValues: Array<string> }): Array<string> {
    const s = handleError(anoncredsReactNative.encodeCredentialAttributes(serializeArguments(options)))
    return s.split(',')
  }

  public processCredential(options: {
    credential: ObjectHandle
    credentialRequestMetadata: ObjectHandle
    linkSecret: string
    credentialDefinition: ObjectHandle
    revocationRegistryDefinition?: ObjectHandle
  }): ObjectHandle {
    const handle = handleError(anoncredsReactNative.processCredential(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public createCredentialOffer(options: {
    schemaId: string
    credentialDefinitionId: string
    keyCorrectnessProof: ObjectHandle
  }): ObjectHandle {
    const handle = handleError(anoncredsReactNative.createCredentialOffer(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public createCredentialRequest(options: {
    entropy?: string
    proverDid?: string
    credentialDefinition: ObjectHandle
    linkSecret: string
    linkSecretId: string
    credentialOffer: ObjectHandle
  }): { credentialRequest: ObjectHandle; credentialRequestMetadata: ObjectHandle } {
    const { credentialRequest, credentialRequestMetadata } = handleError(
      anoncredsReactNative.createCredentialRequest(serializeArguments(options))
    )

    return {
      credentialRequestMetadata: new ObjectHandle(credentialRequestMetadata),
      credentialRequest: new ObjectHandle(credentialRequest),
    }
  }

  public createLinkSecret(): string {
    return handleError(anoncredsReactNative.createLinkSecret({}))
  }

  public createPresentation(options: {
    presentationRequest: ObjectHandle
    credentials: NativeCredentialEntry[]
    credentialsProve: NativeCredentialProve[]
    selfAttest: Record<string, string>
    linkSecret: string
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
      revocationState: value.revocationState?.handle ?? 0,
    }))

    const handle = handleError(
      anoncredsReactNative.createPresentation({
        presentationRequest: options.presentationRequest.handle,
        linkSecret: options.linkSecret,
        credentialsProve: options.credentialsProve,
        selfAttestNames,
        selfAttestValues,
        credentials: credentialEntries,
        schemas: schemaValues,
        schemaIds: schemaKeys,
        credentialDefinitions: credentialDefinitionValues,
        credentialDefinitionIds: credentialDefinitionKeys,
      })
    )
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
    revocationRegistryDefinitionIds?: string[]
    revocationStatusLists?: ObjectHandle[]
    nonRevokedIntervalOverrides?: NativeNonRevokedIntervalOverride[]
  }): boolean {
    return Boolean(handleError(anoncredsReactNative.verifyPresentation(serializeArguments(options))))
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
    const { registryDefinition, registryDefinitionPrivate } = handleError(
      anoncredsReactNative.createRevocationRegistryDefinition(serializeArguments(options))
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
    const handle = handleError(anoncredsReactNative.createOrUpdateRevocationState(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public presentationRequestFromJson(options: { json: string }): ObjectHandle {
    const handle = handleError(anoncredsReactNative.presentationRequestFromJson(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public schemaGetAttribute(options: { objectHandle: ObjectHandle; name: string }): string {
    return handleError(anoncredsReactNative.schemaGetAttribute(serializeArguments(options)))
  }

  public revocationRegistryDefinitionGetAttribute(options: { objectHandle: ObjectHandle; name: string }): string {
    return handleError(anoncredsReactNative.revocationRegistryDefinitionGetAttribute(serializeArguments(options)))
  }

  public credentialGetAttribute(options: { objectHandle: ObjectHandle; name: string }): string {
    return handleError(anoncredsReactNative.credentialGetAttribute(serializeArguments(options)))
  }

  public getJson(options: { objectHandle: ObjectHandle }): string {
    return handleError(anoncredsReactNative.getJson(serializeArguments(options)))
  }

  public getTypeName(options: { objectHandle: ObjectHandle }): string {
    return handleError(anoncredsReactNative.getTypeName(serializeArguments(options)))
  }

  public objectFree(options: { objectHandle: ObjectHandle }): void {
    return handleError(anoncredsReactNative.objectFree(serializeArguments(options)))
  }

  public credentialDefinitionGetAttribute(options: { objectHandle: ObjectHandle; name: string }): string {
    return handleError(anoncredsReactNative.credentialDefinitionGetAttribute(serializeArguments(options)))
  }

  public revocationRegistryDefinitionFromJson(options: { json: string }): ObjectHandle {
    const handle = handleError(anoncredsReactNative.revocationRegistryFromJson(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public revocationRegistryFromJson(options: { json: string }): ObjectHandle {
    const handle = handleError(anoncredsReactNative.revocationRegistryFromJson(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public presentationFromJson(options: { json: string }): ObjectHandle {
    const handle = handleError(anoncredsReactNative.presentationFromJson(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public credentialOfferFromJson(options: { json: string }): ObjectHandle {
    const handle = handleError(anoncredsReactNative.credentialOfferFromJson(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public schemaFromJson(options: { json: string }): ObjectHandle {
    const handle = handleError(anoncredsReactNative.schemaFromJson(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public credentialRequestFromJson(options: { json: string }): ObjectHandle {
    const handle = handleError(anoncredsReactNative.credentialRequestFromJson(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public credentialRequestMetadataFromJson(options: { json: string }): ObjectHandle {
    const handle = handleError(anoncredsReactNative.credentialRequestMetadataFromJson(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public credentialFromJson(options: { json: string }): ObjectHandle {
    const handle = handleError(anoncredsReactNative.credentialFromJson(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public revocationRegistryDefinitionPrivateFromJson(options: { json: string }): ObjectHandle {
    const handle = handleError(
      anoncredsReactNative.revocationRegistryDefinitionPrivateFromJson(serializeArguments(options))
    )
    return new ObjectHandle(handle)
  }

  public revocationRegistryDeltaFromJson(options: { json: string }): ObjectHandle {
    const handle = handleError(anoncredsReactNative.revocationRegistryDeltaFromJson(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public revocationStateFromJson(options: { json: string }): ObjectHandle {
    const handle = handleError(anoncredsReactNative.revocationStateFromJson(serializeArguments(options)))
    return new ObjectHandle(handle)
  }
  public credentialDefinitionFromJson(options: { json: string }): ObjectHandle {
    const handle = handleError(anoncredsReactNative.credentialDefinitionFromJson(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public credentialDefinitionPrivateFromJson(options: { json: string }): ObjectHandle {
    const handle = handleError(anoncredsReactNative.credentialDefinitionPrivateFromJson(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public keyCorrectnessProofFromJson(options: { json: string }): ObjectHandle {
    const handle = handleError(anoncredsReactNative.keyCorrectnessProofFromJson(serializeArguments(options)))
    return new ObjectHandle(handle)
  }
}
