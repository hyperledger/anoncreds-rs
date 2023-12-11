import type { NativeBindings } from './NativeBindings'
import type { ReturnObject } from './serialize'
import type {
  Anoncreds,
  AnoncredsErrorObject,
  NativeCredentialEntry,
  NativeCredentialProve,
  NativeCredentialRevocationConfig,
  NativeNonRevokedIntervalOverride
} from '@hyperledger/anoncreds-shared'

import { ObjectHandle, AnoncredsError } from '@hyperledger/anoncreds-shared'

import { serializeArguments } from './serialize'

export class ReactNativeAnoncreds implements Anoncreds {
  private readonly anoncreds: NativeBindings

  public constructor(bindings: NativeBindings) {
    this.anoncreds = bindings
  }

  private handleError<T>({ errorCode, value }: ReturnObject<T>): T {
    if (errorCode !== 0) {
      throw new AnoncredsError(JSON.parse(this.getCurrentError()) as AnoncredsErrorObject)
    }

    return value as T
  }

  public createRevocationStatusList(options: {
    credentialDefinition: ObjectHandle
    revocationRegistryDefinitionId: string
    revocationRegistryDefinition: ObjectHandle
    revocationRegistryDefinitionPrivate: ObjectHandle
    issuerId: string
    timestamp?: number
    issuanceByDefault: boolean
  }): ObjectHandle {
    const handle = this.handleError(
      this.anoncreds.createRevocationStatusList(serializeArguments({ ...options, timestamp: options.timestamp ?? -1 }))
    )
    return new ObjectHandle(handle)
  }

  public updateRevocationStatusListTimestampOnly(options: {
    timestamp: number
    currentRevocationStatusList: ObjectHandle
  }): ObjectHandle {
    const handle = this.handleError(this.anoncreds.updateRevocationStatusListTimestampOnly(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public updateRevocationStatusList(options: {
    credentialDefinition: ObjectHandle
    revocationRegistryDefinition: ObjectHandle
    revocationRegistryDefinitionPrivate: ObjectHandle
    currentRevocationStatusList: ObjectHandle
    issued?: number[]
    revoked?: number[]
    timestamp?: number
  }): ObjectHandle {
    const handle = this.handleError(this.anoncreds.updateRevocationStatusList(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public version(): string {
    return this.anoncreds.version({})
  }

  public setDefaultLogger(): void {
    this.anoncreds.setDefaultLogger({})
  }

  public getCurrentError(): string {
    return this.anoncreds.getCurrentError({})
  }

  public generateNonce(): string {
    return this.handleError(this.anoncreds.generateNonce({}))
  }

  public createSchema(options: {
    name: string
    version: string
    attributeNames: string[]
    issuerId: string
  }): ObjectHandle {
    const handle = this.handleError(this.anoncreds.createSchema(serializeArguments(options)))
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
    const { keyCorrectnessProof, credentialDefinition, credentialDefinitionPrivate } = this.handleError(
      this.anoncreds.createCredentialDefinition(serializeArguments(options))
    )

    return {
      credentialDefinitionPrivate: new ObjectHandle(credentialDefinitionPrivate),
      credentialDefinition: new ObjectHandle(credentialDefinition),
      keyCorrectnessProof: new ObjectHandle(keyCorrectnessProof)
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
    const attributeNames = Object.keys(options.attributeRawValues)
    const attributeRawValues = Object.values(options.attributeRawValues)
    const attributeEncodedValues = options.attributeEncodedValues
      ? Object.values(options.attributeEncodedValues)
      : undefined

    const credential = this.handleError(
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment, @typescript-eslint/prefer-ts-expect-error
      // @ts-ignore
      this.anoncreds.createCredential({
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment, @typescript-eslint/prefer-ts-expect-error
        // @ts-ignore
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
              revocationStatusList: options.revocationConfiguration.revocationStatusList.handle
            }
          : undefined
      })
    )

    return new ObjectHandle(credential)
  }

  public encodeCredentialAttributes(options: { attributeRawValues: string[] }): string[] {
    const s = this.handleError(this.anoncreds.encodeCredentialAttributes(serializeArguments(options)))
    return s.split(',')
  }

  public processCredential(options: {
    credential: ObjectHandle
    credentialRequestMetadata: ObjectHandle
    linkSecret: string
    credentialDefinition: ObjectHandle
    revocationRegistryDefinition?: ObjectHandle
  }): ObjectHandle {
    const handle = this.handleError(this.anoncreds.processCredential(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public createCredentialOffer(options: {
    schemaId: string
    credentialDefinitionId: string
    keyCorrectnessProof: ObjectHandle
  }): ObjectHandle {
    const handle = this.handleError(this.anoncreds.createCredentialOffer(serializeArguments(options)))
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
    const { credentialRequest, credentialRequestMetadata } = this.handleError(
      this.anoncreds.createCredentialRequest(serializeArguments(options))
    )

    return {
      credentialRequestMetadata: new ObjectHandle(credentialRequestMetadata),
      credentialRequest: new ObjectHandle(credentialRequest)
    }
  }

  public createLinkSecret(): string {
    return this.handleError(this.anoncreds.createLinkSecret({}))
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
      revocationState: value.revocationState?.handle ?? 0
    }))

    const handle = this.handleError(
      this.anoncreds.createPresentation({
        presentationRequest: options.presentationRequest.handle,
        linkSecret: options.linkSecret,
        credentialsProve: options.credentialsProve,
        selfAttestNames,
        selfAttestValues,
        credentials: credentialEntries,
        schemas: schemaValues,
        schemaIds: schemaKeys,
        credentialDefinitions: credentialDefinitionValues,
        credentialDefinitionIds: credentialDefinitionKeys
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
    return Boolean(this.handleError(this.anoncreds.verifyPresentation(serializeArguments(options))))
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
    const { registryDefinition, registryDefinitionPrivate } = this.handleError(
      this.anoncreds.createRevocationRegistryDefinition(serializeArguments(options))
    )

    return {
      revocationRegistryDefinitionPrivate: new ObjectHandle(registryDefinitionPrivate),
      revocationRegistryDefinition: new ObjectHandle(registryDefinition)
    }
  }

  public createOrUpdateRevocationState(options: {
    revocationRegistryDefinition: ObjectHandle
    revocationStatusList: ObjectHandle
    revocationRegistryIndex: number
    tailsPath: string
    oldRevocationState?: ObjectHandle
    oldRevocationStatusList?: ObjectHandle
  }): ObjectHandle {
    const handle = this.handleError(this.anoncreds.createOrUpdateRevocationState(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public presentationRequestFromJson(options: { json: string }): ObjectHandle {
    const handle = this.handleError(this.anoncreds.presentationRequestFromJson(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public schemaGetAttribute(options: { objectHandle: ObjectHandle; name: string }): string {
    return this.handleError(this.anoncreds.schemaGetAttribute(serializeArguments(options)))
  }

  public revocationRegistryDefinitionGetAttribute(options: { objectHandle: ObjectHandle; name: string }): string {
    return this.handleError(this.anoncreds.revocationRegistryDefinitionGetAttribute(serializeArguments(options)))
  }

  public credentialGetAttribute(options: { objectHandle: ObjectHandle; name: string }): string {
    return this.handleError(this.anoncreds.credentialGetAttribute(serializeArguments(options)))
  }

  public getJson(options: { objectHandle: ObjectHandle }): string {
    return this.handleError(this.anoncreds.getJson(serializeArguments(options)))
  }

  public getTypeName(options: { objectHandle: ObjectHandle }): string {
    return this.handleError(this.anoncreds.getTypeName(serializeArguments(options)))
  }

  public objectFree(options: { objectHandle: ObjectHandle }): void {
    return this.handleError(this.anoncreds.objectFree(serializeArguments(options)))
  }

  public credentialDefinitionGetAttribute(options: { objectHandle: ObjectHandle; name: string }): string {
    return this.handleError(this.anoncreds.credentialDefinitionGetAttribute(serializeArguments(options)))
  }

  public revocationRegistryDefinitionFromJson(options: { json: string }): ObjectHandle {
    const handle = this.handleError(this.anoncreds.revocationRegistryDefinitionFromJson(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public revocationRegistryFromJson(options: { json: string }): ObjectHandle {
    const handle = this.handleError(this.anoncreds.revocationRegistryFromJson(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public revocationStatusListFromJson(options: { json: string }): ObjectHandle {
    const handle = this.handleError(this.anoncreds.revocationStatusListFromJson(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public presentationFromJson(options: { json: string }): ObjectHandle {
    const handle = this.handleError(this.anoncreds.presentationFromJson(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public credentialOfferFromJson(options: { json: string }): ObjectHandle {
    const handle = this.handleError(this.anoncreds.credentialOfferFromJson(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public schemaFromJson(options: { json: string }): ObjectHandle {
    const handle = this.handleError(this.anoncreds.schemaFromJson(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public credentialRequestFromJson(options: { json: string }): ObjectHandle {
    const handle = this.handleError(this.anoncreds.credentialRequestFromJson(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public credentialRequestMetadataFromJson(options: { json: string }): ObjectHandle {
    const handle = this.handleError(this.anoncreds.credentialRequestMetadataFromJson(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public credentialFromJson(options: { json: string }): ObjectHandle {
    const handle = this.handleError(this.anoncreds.credentialFromJson(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public revocationRegistryDefinitionPrivateFromJson(options: { json: string }): ObjectHandle {
    const handle = this.handleError(
      this.anoncreds.revocationRegistryDefinitionPrivateFromJson(serializeArguments(options))
    )
    return new ObjectHandle(handle)
  }

  public revocationStateFromJson(options: { json: string }): ObjectHandle {
    const handle = this.handleError(this.anoncreds.revocationStateFromJson(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public credentialDefinitionFromJson(options: { json: string }): ObjectHandle {
    const handle = this.handleError(this.anoncreds.credentialDefinitionFromJson(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public credentialDefinitionPrivateFromJson(options: { json: string }): ObjectHandle {
    const handle = this.handleError(this.anoncreds.credentialDefinitionPrivateFromJson(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public keyCorrectnessProofFromJson(options: { json: string }): ObjectHandle {
    const handle = this.handleError(this.anoncreds.keyCorrectnessProofFromJson(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public createW3cCredential(options: {
    credentialDefinition: ObjectHandle
    credentialDefinitionPrivate: ObjectHandle
    credentialOffer: ObjectHandle
    credentialRequest: ObjectHandle
    attributeRawValues: Record<string, string>
    revocationConfiguration?: NativeCredentialRevocationConfig
    encoding?: string
  }): ObjectHandle {
    const attributeNames = Object.keys(options.attributeRawValues)
    const attributeRawValues = Object.values(options.attributeRawValues)

    const credential = this.handleError(
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment, @typescript-eslint/prefer-ts-expect-error
      // @ts-ignore
      this.anoncreds.createW3cCredential({
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment, @typescript-eslint/prefer-ts-expect-error
        // @ts-ignore
        ...serializeArguments(options),
        attributeRawValues,
        attributeNames,
        revocationConfiguration: options.revocationConfiguration
          ? {
              registryIndex: options.revocationConfiguration.registryIndex,
              revocationRegistryDefinition: options.revocationConfiguration.revocationRegistryDefinition.handle,
              revocationRegistryDefinitionPrivate:
                options.revocationConfiguration.revocationRegistryDefinitionPrivate.handle,
              revocationStatusList: options.revocationConfiguration.revocationStatusList.handle
            }
          : undefined,
        encoding: options.encoding
      })
    )

    return new ObjectHandle(credential)
  }

  public processW3cCredential(options: {
    credential: ObjectHandle
    credentialRequestMetadata: ObjectHandle
    linkSecret: string
    credentialDefinition: ObjectHandle
    revocationRegistryDefinition?: ObjectHandle
  }): ObjectHandle {
    const handle = this.handleError(this.anoncreds.processW3cCredential(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public createW3cCredentialOffer(options: {
    schemaId: string
    credentialDefinitionId: string
    keyCorrectnessProof: ObjectHandle
  }): ObjectHandle {
    const handle = this.handleError(this.anoncreds.createW3cCredentialOffer(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public createW3cCredentialRequest(options: {
    entropy?: string
    proverDid?: string
    credentialDefinition: ObjectHandle
    linkSecret: string
    linkSecretId: string
    credentialOffer: ObjectHandle
  }): { credentialRequest: ObjectHandle; credentialRequestMetadata: ObjectHandle } {
    const { credentialRequest, credentialRequestMetadata } = this.handleError(
      this.anoncreds.createW3cCredentialRequest(serializeArguments(options))
    )

    return {
      credentialRequestMetadata: new ObjectHandle(credentialRequestMetadata),
      credentialRequest: new ObjectHandle(credentialRequest)
    }
  }

  public createW3cPresentation(options: {
    presentationRequest: ObjectHandle
    credentials: NativeCredentialEntry[]
    credentialsProve: NativeCredentialProve[]
    linkSecret: string
    schemas: Record<string, ObjectHandle>
    credentialDefinitions: Record<string, ObjectHandle>
  }): ObjectHandle {
    const schemaKeys = Object.keys(options.schemas)
    const schemaValues = Object.values(options.schemas).map((o) => o.handle)
    const credentialDefinitionKeys = Object.keys(options.credentialDefinitions)
    const credentialDefinitionValues = Object.values(options.credentialDefinitions).map((o) => o.handle)

    const credentialEntries = options.credentials.map((value) => ({
      credential: value.credential.handle,
      timestamp: value.timestamp ?? -1,
      revocationState: value.revocationState?.handle ?? 0
    }))

    const handle = this.handleError(
      this.anoncreds.createW3cPresentation({
        presentationRequest: options.presentationRequest.handle,
        linkSecret: options.linkSecret,
        credentialsProve: options.credentialsProve,
        credentials: credentialEntries,
        schemas: schemaValues,
        schemaIds: schemaKeys,
        credentialDefinitions: credentialDefinitionValues,
        credentialDefinitionIds: credentialDefinitionKeys
      })
    )
    return new ObjectHandle(handle)
  }

  public verifyW3cPresentation(options: {
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
    return Boolean(this.handleError(this.anoncreds.verifyW3cPresentation(serializeArguments(options))))
  }

  public w3cCredentialGetAttribute(options: { objectHandle: ObjectHandle; name: string }): string {
    return this.handleError(this.anoncreds.w3cCredentialGetAttribute(serializeArguments(options)))
  }

  public w3cPresentationFromJson(options: { json: string }): ObjectHandle {
    const handle = this.handleError(this.anoncreds.w3cPresentationFromJson(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public w3cCredentialOfferFromJson(options: { json: string }): ObjectHandle {
    const handle = this.handleError(this.anoncreds.w3cCredentialOfferFromJson(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public w3cCredentialRequestFromJson(options: { json: string }): ObjectHandle {
    const handle = this.handleError(this.anoncreds.w3cCredentialRequestFromJson(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public w3cCredentialFromJson(options: { json: string }): ObjectHandle {
    const handle = this.handleError(this.anoncreds.w3cCredentialFromJson(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public w3cCredentialAddNonAnonCredsIntegrityProof(options: {
    objectHandle: ObjectHandle
    proof: string
  }): ObjectHandle {
    const handle = this.handleError(
      this.anoncreds.w3cCredentialAddNonAnonCredsIntegrityProof(serializeArguments(options))
    )
    return new ObjectHandle(handle)
  }

  public w3cCredentialSetId(options: { objectHandle: ObjectHandle; id: string }): ObjectHandle {
    const handle = this.handleError(this.anoncreds.w3cCredentialSetId(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public w3cCredentialSetSubjectId(options: { objectHandle: ObjectHandle; id: string }): ObjectHandle {
    const handle = this.handleError(this.anoncreds.w3cCredentialSetSubjectId(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public w3cCredentialAddContext(options: { objectHandle: ObjectHandle; context: string }): ObjectHandle {
    const handle = this.handleError(this.anoncreds.w3cCredentialAddContext(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public w3cCredentialAddType(options: { objectHandle: ObjectHandle; type: string }): ObjectHandle {
    const handle = this.handleError(this.anoncreds.w3cCredentialAddType(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public credentialToW3c(options: { objectHandle: ObjectHandle; credentialDefinition: ObjectHandle }): ObjectHandle {
    const handle = this.handleError(this.anoncreds.credentialToW3c(serializeArguments(options)))
    return new ObjectHandle(handle)
  }

  public credentialFromW3c(options: { objectHandle: ObjectHandle }): ObjectHandle {
    const handle = this.handleError(this.anoncreds.credentialFromW3c(serializeArguments(options)))
    return new ObjectHandle(handle)
  }
}
