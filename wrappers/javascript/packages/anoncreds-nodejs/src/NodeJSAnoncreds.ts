import type {
  NativeCredentialEntry,
  NativeCredentialProve,
  Anoncreds,
  NativeCredentialRevocationConfig,
  NativeNonRevokedIntervalOverride,
  AnoncredsErrorObject
} from '@hyperledger/anoncreds-shared'
import type { TypedArray } from 'ref-array-di'
import type { StructObject } from 'ref-struct-di'

import { AnoncredsError, ByteBuffer, ObjectHandle } from '@hyperledger/anoncreds-shared'
import { TextDecoder, TextEncoder } from 'util'

import {
  byteBufferToBuffer,
  allocateStringBuffer,
  allocatePointer,
  serializeArguments,
  StringListStruct,
  CredentialEntryStruct,
  CredentialProveStruct,
  CredentialEntryListStruct,
  CredentialProveListStruct,
  allocateInt8Buffer,
  CredRevInfoStruct,
  allocateByteBuffer,
  ObjectHandleListStruct,
  ObjectHandleArray,
  NonRevokedIntervalOverrideStruct,
  NonRevokedIntervalOverrideListStruct
} from './ffi'
import { getNativeAnoncreds } from './library'

function handleReturnPointer<Return>(returnValue: Buffer, cleanupCallback?: (buffer: Buffer) => void): Return {
  if (returnValue.address() === 0) {
    throw AnoncredsError.customError({ message: 'Unexpected null pointer' })
  }

  const ret = returnValue.deref() as Return
  if (cleanupCallback) cleanupCallback(returnValue)

  return ret
}

export class NodeJSAnoncreds implements Anoncreds {
  private handleError() {
    const nativeError = allocateStringBuffer()
    getNativeAnoncreds().anoncreds_get_current_error(nativeError)
    const anoncredsErrorObject = JSON.parse(nativeError.deref() as string) as AnoncredsErrorObject

    if (anoncredsErrorObject.code === 0) return

    throw new AnoncredsError(anoncredsErrorObject)
  }

  public get nativeAnoncreds() {
    return getNativeAnoncreds()
  }

  public generateNonce(): string {
    const ret = allocateStringBuffer()
    this.nativeAnoncreds.anoncreds_generate_nonce(ret)
    this.handleError()

    return handleReturnPointer<string>(ret)
  }

  public createSchema(options: {
    name: string
    version: string
    issuerId: string
    attributeNames: string[]
  }): ObjectHandle {
    const { name, version, issuerId, attributeNames } = serializeArguments(options)

    const ret = allocatePointer()

    this.nativeAnoncreds.anoncreds_create_schema(name, version, issuerId, attributeNames, ret)
    this.handleError()

    return new ObjectHandle(handleReturnPointer<number>(ret))
  }

  public revocationRegistryDefinitionGetAttribute(options: { objectHandle: ObjectHandle; name: string }) {
    const { objectHandle, name } = serializeArguments(options)

    const ret = allocateStringBuffer()
    this.nativeAnoncreds.anoncreds_revocation_registry_definition_get_attribute(objectHandle, name, ret)
    this.handleError()

    return handleReturnPointer<string>(ret)
  }

  public credentialGetAttribute(options: { objectHandle: ObjectHandle; name: string }) {
    const { objectHandle, name } = serializeArguments(options)

    const ret = allocateStringBuffer()
    this.nativeAnoncreds.anoncreds_credential_get_attribute(objectHandle, name, ret)
    this.handleError()

    return handleReturnPointer<string>(ret)
  }

  public createCredentialDefinition(options: {
    schemaId: string
    schema: ObjectHandle
    issuerId: string
    tag: string
    signatureType: string
    supportRevocation: boolean
  }): {
    credentialDefinition: ObjectHandle
    credentialDefinitionPrivate: ObjectHandle
    keyCorrectnessProof: ObjectHandle
  } {
    const { schemaId, issuerId, schema, tag, signatureType, supportRevocation } = serializeArguments(options)

    const credentialDefinitionPtr = allocatePointer()
    const credentialDefinitionPrivatePtr = allocatePointer()
    const keyCorrectnessProofPtr = allocatePointer()

    this.nativeAnoncreds.anoncreds_create_credential_definition(
      schemaId,
      schema,
      tag,
      issuerId,
      signatureType,
      supportRevocation,
      credentialDefinitionPtr,
      credentialDefinitionPrivatePtr,
      keyCorrectnessProofPtr
    )
    this.handleError()

    return {
      credentialDefinition: new ObjectHandle(handleReturnPointer<number>(credentialDefinitionPtr)),
      credentialDefinitionPrivate: new ObjectHandle(handleReturnPointer<number>(credentialDefinitionPrivatePtr)),
      keyCorrectnessProof: new ObjectHandle(handleReturnPointer<number>(keyCorrectnessProofPtr))
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
    const { credentialDefinition, credentialDefinitionPrivate, credentialOffer, credentialRequest } =
      serializeArguments(options)

    const attributeNames = this.convertAttributeNames(options.attributeRawValues)
    const attributeRawValues = this.convertAttributeRawValues(options.attributeRawValues)
    const attributeEncodedValues = this.convertAttributeEncodedValues(options.attributeEncodedValues)
    const revocationConfiguration = this.convertRevocationConfiguration(options.revocationConfiguration)

    const credentialPtr = allocatePointer()
    this.nativeAnoncreds.anoncreds_create_credential(
      credentialDefinition,
      credentialDefinitionPrivate,
      credentialOffer,
      credentialRequest,
      attributeNames,
      attributeRawValues,
      attributeEncodedValues as unknown as Buffer,
      revocationConfiguration?.ref().address() ?? 0,
      credentialPtr
    )
    this.handleError()

    return new ObjectHandle(handleReturnPointer<number>(credentialPtr))
  }

  public encodeCredentialAttributes(options: { attributeRawValues: string[] }): string[] {
    const { attributeRawValues } = serializeArguments(options)

    const ret = allocateStringBuffer()

    this.nativeAnoncreds.anoncreds_encode_credential_attributes(attributeRawValues, ret)
    this.handleError()

    const result = handleReturnPointer<string>(ret)

    return result.split(',')
  }

  public processCredential(options: {
    credential: ObjectHandle
    credentialRequestMetadata: ObjectHandle
    linkSecret: string
    credentialDefinition: ObjectHandle
    revocationRegistryDefinition?: ObjectHandle | undefined
  }): ObjectHandle {
    const { credential, credentialRequestMetadata, linkSecret, credentialDefinition } = serializeArguments(options)

    const ret = allocatePointer()

    this.nativeAnoncreds.anoncreds_process_credential(
      credential,
      credentialRequestMetadata,
      linkSecret,
      credentialDefinition,
      options.revocationRegistryDefinition?.handle ?? 0,
      ret
    )
    this.handleError()

    return new ObjectHandle(handleReturnPointer<number>(ret))
  }

  public createCredentialOffer(options: {
    schemaId: string
    credentialDefinitionId: string
    keyCorrectnessProof: ObjectHandle
  }): ObjectHandle {
    const { schemaId, credentialDefinitionId, keyCorrectnessProof } = serializeArguments(options)

    const ret = allocatePointer()
    this.nativeAnoncreds.anoncreds_create_credential_offer(schemaId, credentialDefinitionId, keyCorrectnessProof, ret)
    this.handleError()

    return new ObjectHandle(handleReturnPointer<number>(ret))
  }

  public createCredentialRequest(options: {
    entropy?: string
    proverDid?: string
    credentialDefinition: ObjectHandle
    linkSecret: string
    linkSecretId: string
    credentialOffer: ObjectHandle
  }): { credentialRequest: ObjectHandle; credentialRequestMetadata: ObjectHandle } {
    const { entropy, proverDid, credentialDefinition, linkSecret, linkSecretId, credentialOffer } =
      serializeArguments(options)

    const credentialRequestPtr = allocatePointer()
    const credentialRequestMetadataPtr = allocatePointer()

    this.nativeAnoncreds.anoncreds_create_credential_request(
      entropy,
      proverDid,
      credentialDefinition,
      linkSecret,
      linkSecretId,
      credentialOffer,
      credentialRequestPtr,
      credentialRequestMetadataPtr
    )
    this.handleError()

    return {
      credentialRequest: new ObjectHandle(handleReturnPointer<number>(credentialRequestPtr)),
      credentialRequestMetadata: new ObjectHandle(handleReturnPointer<number>(credentialRequestMetadataPtr))
    }
  }

  public createLinkSecret(): string {
    const ret = allocateStringBuffer()

    this.nativeAnoncreds.anoncreds_create_link_secret(ret)
    this.handleError()

    return handleReturnPointer<string>(ret)
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
    const { presentationRequest, linkSecret } = serializeArguments(options)

    const selfAttestNames = StringListStruct({
      count: Object.keys(options.selfAttest).length,
      data: Object.keys(options.selfAttest) as unknown as TypedArray<string>
    })

    const selfAttestValues = StringListStruct({
      count: Object.values(options.selfAttest).length,
      data: Object.values(options.selfAttest) as unknown as TypedArray<string>
    })

    const credentialEntryList = this.convertCredentialList(options.credentials)
    const credentialProveList = this.convertCredentialProves(options.credentialsProve)
    const { schemaIds, schemas } = this.convertSchemas(options.schemas)
    const { credentialDefinitionIds, credentialDefinitions } = this.convertCredDefs(options.credentialDefinitions)

    const ret = allocatePointer()

    this.nativeAnoncreds.anoncreds_create_presentation(
      presentationRequest,
      credentialEntryList,
      credentialProveList,
      selfAttestNames as unknown as Buffer,
      selfAttestValues as unknown as Buffer,
      linkSecret,
      schemas,
      schemaIds,
      credentialDefinitions,
      credentialDefinitionIds,
      ret
    )
    this.handleError()

    return new ObjectHandle(handleReturnPointer<number>(ret))
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
    const {
      presentation,
      presentationRequest,
      schemas,
      credentialDefinitions,
      revocationRegistryDefinitions,
      revocationStatusLists,
      revocationRegistryDefinitionIds,
      schemaIds,
      credentialDefinitionIds
    } = serializeArguments(options)

    const nonRevokedIntervalOverrideList = this.convertNonRevokedIntervalOverrides(options.nonRevokedIntervalOverrides)

    const ret = allocateInt8Buffer()

    this.nativeAnoncreds.anoncreds_verify_presentation(
      presentation,
      presentationRequest,
      schemas,
      schemaIds,
      credentialDefinitions,
      credentialDefinitionIds,
      revocationRegistryDefinitions,
      revocationRegistryDefinitionIds,
      revocationStatusLists,
      nonRevokedIntervalOverrideList,
      ret
    )
    this.handleError()

    return Boolean(handleReturnPointer<number>(ret))
  }

  public createRevocationStatusList(options: {
    credentialDefinition: ObjectHandle
    revocationRegistryDefinitionId: string
    revocationRegistryDefinition: ObjectHandle
    revocationRegistryDefinitionPrivate: ObjectHandle
    issuerId: string
    issuanceByDefault: boolean
    timestamp?: number
  }): ObjectHandle {
    const {
      credentialDefinition,
      revocationRegistryDefinitionId,
      revocationRegistryDefinition,
      revocationRegistryDefinitionPrivate,
      issuerId,
      issuanceByDefault,
      timestamp
    } = serializeArguments(options)

    const ret = allocatePointer()

    this.nativeAnoncreds.anoncreds_create_revocation_status_list(
      credentialDefinition,
      revocationRegistryDefinitionId,
      revocationRegistryDefinition,
      revocationRegistryDefinitionPrivate,
      issuerId,
      issuanceByDefault,
      timestamp ?? -1,
      ret
    )
    this.handleError()

    return new ObjectHandle(handleReturnPointer<number>(ret))
  }

  public updateRevocationStatusListTimestampOnly(options: {
    timestamp: number
    currentRevocationStatusList: ObjectHandle
  }): ObjectHandle {
    const { currentRevocationStatusList, timestamp } = serializeArguments(options)
    const ret = allocatePointer()

    this.nativeAnoncreds.anoncreds_update_revocation_status_list_timestamp_only(
      timestamp,
      currentRevocationStatusList,
      ret
    )
    this.handleError()

    return new ObjectHandle(handleReturnPointer<number>(ret))
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
    const {
      credentialDefinition,
      revocationRegistryDefinition,
      revocationRegistryDefinitionPrivate,
      currentRevocationStatusList,
      issued,
      revoked,
      timestamp
    } = serializeArguments(options)
    const ret = allocatePointer()

    this.nativeAnoncreds.anoncreds_update_revocation_status_list(
      credentialDefinition,
      revocationRegistryDefinition,
      revocationRegistryDefinitionPrivate,
      currentRevocationStatusList,
      issued,
      revoked,
      timestamp ?? -1,
      ret
    )
    this.handleError()

    return new ObjectHandle(handleReturnPointer<number>(ret))
  }

  public createRevocationRegistryDefinition(options: {
    credentialDefinition: ObjectHandle
    credentialDefinitionId: string
    issuerId: string
    tag: string
    revocationRegistryType: string
    maximumCredentialNumber: number
    tailsDirectoryPath?: string
  }) {
    const {
      credentialDefinition,
      credentialDefinitionId,
      tag,
      revocationRegistryType,
      issuerId,
      maximumCredentialNumber,
      tailsDirectoryPath
    } = serializeArguments(options)

    const revocationRegistryDefinitionPtr = allocatePointer()
    const revocationRegistryDefinitionPrivate = allocatePointer()

    this.nativeAnoncreds.anoncreds_create_revocation_registry_def(
      credentialDefinition,
      credentialDefinitionId,
      issuerId,
      tag,
      revocationRegistryType,
      maximumCredentialNumber,
      tailsDirectoryPath,
      revocationRegistryDefinitionPtr,
      revocationRegistryDefinitionPrivate
    )
    this.handleError()

    return {
      revocationRegistryDefinition: new ObjectHandle(handleReturnPointer<number>(revocationRegistryDefinitionPtr)),
      revocationRegistryDefinitionPrivate: new ObjectHandle(
        handleReturnPointer<number>(revocationRegistryDefinitionPrivate)
      )
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
    const { revocationRegistryDefinition, revocationStatusList, revocationRegistryIndex, tailsPath } =
      serializeArguments(options)

    const oldRevocationState = options.oldRevocationState ?? new ObjectHandle(0)
    const oldRevocationStatusList = options.oldRevocationStatusList ?? new ObjectHandle(0)
    const ret = allocatePointer()

    this.nativeAnoncreds.anoncreds_create_or_update_revocation_state(
      revocationRegistryDefinition,
      revocationStatusList,
      revocationRegistryIndex,
      tailsPath,
      oldRevocationState.handle,
      oldRevocationStatusList.handle,
      ret
    )
    this.handleError()

    return new ObjectHandle(handleReturnPointer<number>(ret))
  }

  public createW3cCredential(options: {
    credentialDefinition: ObjectHandle
    credentialDefinitionPrivate: ObjectHandle
    credentialOffer: ObjectHandle
    credentialRequest: ObjectHandle
    attributeRawValues: Record<string, string>
    revocationConfiguration?: NativeCredentialRevocationConfig
    w3cVersion?: string
  }): ObjectHandle {
    const { credentialDefinition, credentialDefinitionPrivate, credentialOffer, credentialRequest, w3cVersion } =
      serializeArguments(options)

    const attributeNames = this.convertAttributeNames(options.attributeRawValues)
    const attributeRawValues = this.convertAttributeRawValues(options.attributeRawValues)
    const revocationConfiguration = this.convertRevocationConfiguration(options.revocationConfiguration)

    const credentialPtr = allocatePointer()
    this.nativeAnoncreds.anoncreds_create_w3c_credential(
      credentialDefinition,
      credentialDefinitionPrivate,
      credentialOffer,
      credentialRequest,
      attributeNames,
      attributeRawValues,
      revocationConfiguration?.ref().address() ?? 0,
      w3cVersion,
      credentialPtr
    )
    this.handleError()

    return new ObjectHandle(handleReturnPointer<number>(credentialPtr))
  }

  public processW3cCredential(options: {
    credential: ObjectHandle
    credentialRequestMetadata: ObjectHandle
    linkSecret: string
    credentialDefinition: ObjectHandle
    revocationRegistryDefinition?: ObjectHandle | undefined
  }): ObjectHandle {
    const { credential, credentialRequestMetadata, linkSecret, credentialDefinition } = serializeArguments(options)

    const ret = allocatePointer()

    this.nativeAnoncreds.anoncreds_process_w3c_credential(
      credential,
      credentialRequestMetadata,
      linkSecret,
      credentialDefinition,
      options.revocationRegistryDefinition?.handle ?? 0,
      ret
    )
    this.handleError()

    return new ObjectHandle(handleReturnPointer<number>(ret))
  }

  public createW3cPresentation(options: {
    presentationRequest: ObjectHandle
    credentials: NativeCredentialEntry[]
    credentialsProve: NativeCredentialProve[]
    linkSecret: string
    schemas: Record<string, ObjectHandle>
    credentialDefinitions: Record<string, ObjectHandle>
    w3cVersion?: string
  }): ObjectHandle {
    const { presentationRequest, linkSecret, w3cVersion } = serializeArguments(options)

    const credentialEntryList = this.convertCredentialList(options.credentials)
    const credentialProveList = this.convertCredentialProves(options.credentialsProve)
    const { schemaIds, schemas } = this.convertSchemas(options.schemas)
    const { credentialDefinitionIds, credentialDefinitions } = this.convertCredDefs(options.credentialDefinitions)

    const ret = allocatePointer()

    this.nativeAnoncreds.anoncreds_create_w3c_presentation(
      presentationRequest,
      credentialEntryList,
      credentialProveList,
      linkSecret,
      schemas,
      schemaIds,
      credentialDefinitions,
      credentialDefinitionIds,
      w3cVersion,
      ret
    )
    this.handleError()

    return new ObjectHandle(handleReturnPointer<number>(ret))
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
    const {
      presentation,
      presentationRequest,
      schemas,
      credentialDefinitions,
      revocationRegistryDefinitions,
      revocationStatusLists,
      revocationRegistryDefinitionIds,
      schemaIds,
      credentialDefinitionIds
    } = serializeArguments(options)

    const nonRevokedIntervalOverrideList = this.convertNonRevokedIntervalOverrides(options.nonRevokedIntervalOverrides)

    const ret = allocateInt8Buffer()

    this.nativeAnoncreds.anoncreds_verify_w3c_presentation(
      presentation,
      presentationRequest,
      schemas,
      schemaIds,
      credentialDefinitions,
      credentialDefinitionIds,
      revocationRegistryDefinitions,
      revocationRegistryDefinitionIds,
      revocationStatusLists,
      nonRevokedIntervalOverrideList,
      ret
    )
    this.handleError()

    return Boolean(handleReturnPointer<number>(ret))
  }

  public credentialToW3c(options: {
    objectHandle: ObjectHandle
    credentialDefinition: ObjectHandle
    w3cVersion?: string
  }): ObjectHandle {
    const { objectHandle, credentialDefinition, w3cVersion } = serializeArguments(options)

    const ret = allocatePointer()

    this.nativeAnoncreds.anoncreds_credential_to_w3c(objectHandle, credentialDefinition, w3cVersion, ret)
    this.handleError()

    return new ObjectHandle(handleReturnPointer<number>(ret))
  }

  public credentialFromW3c(options: { objectHandle: ObjectHandle }): ObjectHandle {
    const { objectHandle } = serializeArguments(options)

    const ret = allocatePointer()

    this.nativeAnoncreds.anoncreds_credential_from_w3c(objectHandle, ret)
    this.handleError()

    return new ObjectHandle(handleReturnPointer<number>(ret))
  }

  public w3cCredentialGetIntegrityProofDetails(options: { objectHandle: ObjectHandle }) {
    const { objectHandle } = serializeArguments(options)

    const ret = allocatePointer()
    this.nativeAnoncreds.anoncreds_w3c_credential_get_integrity_proof_details(objectHandle, ret)
    this.handleError()

    return new ObjectHandle(handleReturnPointer<number>(ret))
  }

  public w3cCredentialProofGetAttribute(options: { objectHandle: ObjectHandle; name: string }) {
    const { objectHandle, name } = serializeArguments(options)

    const ret = allocateStringBuffer()
    this.nativeAnoncreds.anoncreds_w3c_credential_proof_get_attribute(objectHandle, name, ret)
    this.handleError()

    return handleReturnPointer<string>(ret)
  }

  public w3cCredentialFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(this.nativeAnoncreds.anoncreds_w3c_credential_from_json, options)
  }

  public w3cPresentationFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(this.nativeAnoncreds.anoncreds_w3c_presentation_from_json, options)
  }

  public version(): string {
    return this.nativeAnoncreds.anoncreds_version()
  }

  public setDefaultLogger(): void {
    this.nativeAnoncreds.anoncreds_set_default_logger()
    this.handleError()
  }

  // This should be called when a function returns a non-zero code
  public getCurrentError(): string {
    const ret = allocateStringBuffer()
    this.nativeAnoncreds.anoncreds_get_current_error(ret)
    this.handleError()

    return handleReturnPointer<string>(ret)
  }

  private objectFromJson(method: (byteBuffer: Buffer, ret: Buffer) => unknown, options: { json: string }) {
    const ret = allocatePointer()

    const byteBuffer = ByteBuffer.fromUint8Array(new TextEncoder().encode(options.json))
    this.handleError()

    method(byteBuffer as unknown as Buffer, ret)

    return new ObjectHandle(handleReturnPointer<number>(ret))
  }

  public presentationRequestFromJson(options: { json: string }) {
    return this.objectFromJson(this.nativeAnoncreds.anoncreds_presentation_request_from_json, options)
  }

  public credentialRequestFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(this.nativeAnoncreds.anoncreds_credential_request_from_json, options)
  }

  public credentialRequestMetadataFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(this.nativeAnoncreds.anoncreds_credential_request_metadata_from_json, options)
  }

  public revocationRegistryDefinitionFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(this.nativeAnoncreds.anoncreds_revocation_registry_definition_from_json, options)
  }

  public revocationRegistryFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(this.nativeAnoncreds.anoncreds_revocation_registry_from_json, options)
  }

  public revocationStatusListFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(this.nativeAnoncreds.anoncreds_revocation_status_list_from_json, options)
  }

  public revocationStateFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(this.nativeAnoncreds.anoncreds_revocation_state_from_json, options)
  }

  public presentationFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(this.nativeAnoncreds.anoncreds_presentation_from_json, options)
  }

  public credentialOfferFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(this.nativeAnoncreds.anoncreds_credential_offer_from_json, options)
  }

  public schemaFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(this.nativeAnoncreds.anoncreds_schema_from_json, options)
  }

  public credentialFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(this.nativeAnoncreds.anoncreds_credential_from_json, options)
  }

  public revocationRegistryDefinitionPrivateFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(this.nativeAnoncreds.anoncreds_revocation_registry_definition_private_from_json, options)
  }

  public credentialDefinitionFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(this.nativeAnoncreds.anoncreds_credential_definition_from_json, options)
  }

  public credentialDefinitionPrivateFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(this.nativeAnoncreds.anoncreds_credential_definition_private_from_json, options)
  }

  public keyCorrectnessProofFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(this.nativeAnoncreds.anoncreds_key_correctness_proof_from_json, options)
  }

  public getJson(options: { objectHandle: ObjectHandle }) {
    const ret = allocateByteBuffer()

    const { objectHandle } = serializeArguments(options)
    this.nativeAnoncreds.anoncreds_object_get_json(objectHandle, ret)
    this.handleError()

    const returnValue = handleReturnPointer<{ data: Buffer; len: number }>(ret)
    const jsonAsArray = new Uint8Array(byteBufferToBuffer(returnValue))

    const output = new TextDecoder().decode(jsonAsArray)

    this.nativeAnoncreds.anoncreds_buffer_free(returnValue.data)

    return output
  }

  public getTypeName(options: { objectHandle: ObjectHandle }) {
    const { objectHandle } = serializeArguments(options)

    const ret = allocateStringBuffer()

    this.nativeAnoncreds.anoncreds_object_get_type_name(objectHandle, ret)
    this.handleError()

    return handleReturnPointer<string>(ret)
  }

  public objectFree(options: { objectHandle: ObjectHandle }) {
    this.nativeAnoncreds.anoncreds_object_free(options.objectHandle.handle)
    this.handleError()
  }

  private convertCredentialList(credentials: NativeCredentialEntry[]) {
    const credentialEntries = credentials.map((value) =>
      CredentialEntryStruct({
        credential: value.credential.handle,
        timestamp: value.timestamp ?? -1,
        rev_state: value.revocationState?.handle ?? 0
      })
    )

    return CredentialEntryListStruct({
      count: credentialEntries.length,
      data: credentialEntries as unknown as TypedArray<
        StructObject<{
          credential: number
          timestamp: number
          rev_state: number
        }>
      >
    }) as unknown as Buffer
  }

  private convertCredentialProves(credentialsProve: NativeCredentialProve[]) {
    const credentialProves = credentialsProve.map((value) => {
      const { entryIndex: entry_idx, isPredicate: is_predicate, reveal, referent } = serializeArguments(value)
      return CredentialProveStruct({ entry_idx, referent, is_predicate, reveal })
    })

    return CredentialProveListStruct({
      count: credentialProves.length,
      data: credentialProves as unknown as TypedArray<
        StructObject<{
          entry_idx: string | number
          referent: string
          is_predicate: number
          reveal: number
        }>
      >
    }) as unknown as Buffer
  }

  private convertSchemas(schemas: Record<string, ObjectHandle>) {
    const schemaKeys = Object.keys(schemas)
    const schemaIds = StringListStruct({
      count: schemaKeys.length,
      data: schemaKeys as unknown as TypedArray<string>
    }) as unknown as Buffer

    const schemaValues = Object.values(schemas)
    const schemasList = ObjectHandleListStruct({
      count: schemaValues.length,
      data: ObjectHandleArray(schemaValues.map((o) => o.handle))
    }) as unknown as Buffer
    return {
      schemaIds,
      schemas: schemasList
    }
  }

  private convertCredDefs(credentialDefinitions: Record<string, ObjectHandle>) {
    const credentialDefinitionKeys = Object.keys(credentialDefinitions)
    const credentialDefinitionIds = StringListStruct({
      count: credentialDefinitionKeys.length,
      data: credentialDefinitionKeys as unknown as TypedArray<string>
    }) as unknown as Buffer

    const credentialDefinitionValues = Object.values(credentialDefinitions)
    const credentialDefinitionsList = ObjectHandleListStruct({
      count: credentialDefinitionValues.length,
      data: ObjectHandleArray(credentialDefinitionValues.map((o) => o.handle))
    }) as unknown as Buffer
    return {
      credentialDefinitionIds,
      credentialDefinitions: credentialDefinitionsList
    }
  }

  private convertNonRevokedIntervalOverrides(nonRevokedIntervalOverrides?: NativeNonRevokedIntervalOverride[]) {
    const nativeNonRevokedIntervalOverrides = nonRevokedIntervalOverrides?.map((value) => {
      const { requestedFromTimestamp, revocationRegistryDefinitionId, overrideRevocationStatusListTimestamp } =
        serializeArguments(value)
      return NonRevokedIntervalOverrideStruct({
        rev_reg_def_id: revocationRegistryDefinitionId,
        requested_from_ts: requestedFromTimestamp,
        override_rev_status_list_ts: overrideRevocationStatusListTimestamp
      })
    })

    return NonRevokedIntervalOverrideListStruct({
      count: nonRevokedIntervalOverrides?.length ?? 0,
      data: nativeNonRevokedIntervalOverrides as unknown as TypedArray<
        StructObject<{
          rev_reg_def_id: string
          requested_from_ts: number
          override_rev_status_list_ts: number
        }>
      >
    }) as unknown as Buffer
  }

  private convertAttributeNames(attributeRawValues: Record<string, string>) {
    return StringListStruct({
      count: Object.keys(attributeRawValues).length,
      data: Object.keys(attributeRawValues) as unknown as TypedArray<string>
    }) as unknown as Buffer
  }

  private convertAttributeRawValues(attributeRawValues: Record<string, string>) {
    return StringListStruct({
      count: Object.keys(attributeRawValues).length,
      data: Object.values(attributeRawValues) as unknown as TypedArray<string>
    }) as unknown as Buffer
  }

  private convertAttributeEncodedValues(attributeEncodedValues?: Record<string, string>) {
    return attributeEncodedValues
      ? StringListStruct({
          count: Object.keys(attributeEncodedValues).length,
          data: Object.values(attributeEncodedValues) as unknown as TypedArray<string>
        })
      : undefined
  }

  private convertRevocationConfiguration(revocationConfiguration?: NativeCredentialRevocationConfig) {
    let credRevInfo
    if (revocationConfiguration) {
      const { revocationRegistryDefinition, revocationRegistryDefinitionPrivate, revocationStatusList, registryIndex } =
        serializeArguments(revocationConfiguration)

      credRevInfo = CredRevInfoStruct({
        reg_def: revocationRegistryDefinition,
        reg_def_private: revocationRegistryDefinitionPrivate,
        status_list: revocationStatusList,
        reg_idx: registryIndex
      })
    }
    return credRevInfo
  }
}
