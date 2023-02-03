import type {
  NativeCredentialEntry,
  NativeCredentialProve,
  Anoncreds,
  NativeCredentialRevocationConfig,
} from '@hyperledger/anoncreds-shared'
import type { TypedArray } from 'ref-array-di'
import type { StructObject } from 'ref-struct-di'

import { ByteBuffer, ObjectHandle } from '@hyperledger/anoncreds-shared'
import { TextDecoder, TextEncoder } from 'util'

import { handleError } from './error'
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
} from './ffi'
import { nativeAnoncreds } from './library'

export class NodeJSAnoncreds implements Anoncreds {
  public generateNonce(): string {
    const ret = allocateStringBuffer()
    nativeAnoncreds.anoncreds_generate_nonce(ret)
    handleError()

    return ret.deref() as string
  }

  public createSchema(options: {
    name: string
    version: string
    issuerId: string
    attributeNames: string[]
  }): ObjectHandle {
    const { name, version, issuerId, attributeNames } = serializeArguments(options)

    const ret = allocatePointer()

    nativeAnoncreds.anoncreds_create_schema(name, version, issuerId, attributeNames, ret)
    handleError()

    return new ObjectHandle(ret.deref() as number)
  }

  public revocationRegistryDefinitionGetAttribute(options: { objectHandle: ObjectHandle; name: string }) {
    const { objectHandle, name } = serializeArguments(options)

    const ret = allocateStringBuffer()
    nativeAnoncreds.anoncreds_revocation_registry_definition_get_attribute(objectHandle, name, ret)
    handleError()

    return ret.deref() as string
  }

  public credentialGetAttribute(options: { objectHandle: ObjectHandle; name: string }) {
    const { objectHandle, name } = serializeArguments(options)

    const ret = allocateStringBuffer()
    nativeAnoncreds.anoncreds_credential_get_attribute(objectHandle, name, ret)
    handleError()

    return ret.deref() as string
  }

  public createCredentialDefinition(options: {
    schemaId: string
    schema: ObjectHandle
    issuerId: string
    tag: string
    signatureType: string
    supportRevocation: boolean
  }): { credentialDefinition: ObjectHandle; credentialDefinitionPrivate: ObjectHandle; keyProof: ObjectHandle } {
    const { schemaId, issuerId, schema, tag, signatureType, supportRevocation } = serializeArguments(options)

    const credentialDefinitionPtr = allocatePointer()
    const credentialDefinitionPrivatePtr = allocatePointer()
    const keyProofPtr = allocatePointer()

    nativeAnoncreds.anoncreds_create_credential_definition(
      schemaId,
      schema,
      tag,
      issuerId,
      signatureType,
      supportRevocation,
      credentialDefinitionPtr,
      credentialDefinitionPrivatePtr,
      keyProofPtr
    )
    handleError()

    return {
      credentialDefinition: new ObjectHandle(credentialDefinitionPtr.deref() as number),
      credentialDefinitionPrivate: new ObjectHandle(credentialDefinitionPrivatePtr.deref() as number),
      keyProof: new ObjectHandle(keyProofPtr.deref() as number),
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
    const {
      credentialDefinition,
      credentialDefinitionPrivate,
      credentialOffer,
      credentialRequest,
      revocationRegistryId,
      revocationStatusList,
    } = serializeArguments(options)

    const attributeNames = StringListStruct({
      count: Object.keys(options.attributeRawValues).length,
      data: Object.keys(options.attributeRawValues) as unknown as TypedArray<string>,
    })

    const attributeRawValues = StringListStruct({
      count: Object.keys(options.attributeRawValues).length,
      data: Object.values(options.attributeRawValues) as unknown as TypedArray<string>,
    })

    const attributeEncodedValues = options.attributeEncodedValues
      ? StringListStruct({
          count: Object.keys(options.attributeEncodedValues).length,
          data: Object.values(options.attributeEncodedValues) as unknown as TypedArray<string>,
        })
      : undefined

    let revocationConfiguration = CredRevInfoStruct()
    if (options.revocationConfiguration) {
      const {
        revocationRegistryDefinition: registryDefinition,
        revocationRegistryDefinitionPrivate: registryDefinitionPrivate,
        registryIndex,
        tailsPath,
      } = serializeArguments(options.revocationConfiguration)

      revocationConfiguration = CredRevInfoStruct({
        reg_def: registryDefinition,
        reg_def_private: registryDefinitionPrivate,
        reg_idx: registryIndex,
        tails_path: tailsPath,
      })
    }

    const credentialPtr = allocatePointer()
    nativeAnoncreds.anoncreds_create_credential(
      credentialDefinition,
      credentialDefinitionPrivate,
      credentialOffer,
      credentialRequest,
      attributeNames as unknown as Buffer,
      attributeRawValues as unknown as Buffer,
      attributeEncodedValues as unknown as Buffer,
      revocationRegistryId,
      revocationStatusList,
      revocationConfiguration.ref(),
      credentialPtr
    )
    handleError()

    return new ObjectHandle(credentialPtr.deref() as number)
  }

  public encodeCredentialAttributes(options: { attributeRawValues: Array<string> }): Array<string> {
    const { attributeRawValues } = serializeArguments(options)

    const ret = allocateStringBuffer()

    nativeAnoncreds.anoncreds_encode_credential_attributes(attributeRawValues, ret)
    handleError()

    const result = ret.deref() as string

    return result.split(',')
  }

  public processCredential(options: {
    credential: ObjectHandle
    credentialRequestMetadata: ObjectHandle
    masterSecret: ObjectHandle
    credentialDefinition: ObjectHandle
    revocationRegistryDefinition?: ObjectHandle | undefined
  }): ObjectHandle {
    const { credential, credentialRequestMetadata, masterSecret, credentialDefinition, revocationRegistryDefinition } =
      serializeArguments(options)

    const ret = allocatePointer()

    nativeAnoncreds.anoncreds_process_credential(
      credential,
      credentialRequestMetadata,
      masterSecret,
      credentialDefinition,
      revocationRegistryDefinition,
      ret
    )
    handleError()

    return new ObjectHandle(ret.deref() as number)
  }

  public createCredentialOffer(options: {
    schemaId: string
    credentialDefinitionId: string
    keyProof: ObjectHandle
  }): ObjectHandle {
    const { schemaId, credentialDefinitionId, keyProof } = serializeArguments(options)

    const ret = allocatePointer()
    nativeAnoncreds.anoncreds_create_credential_offer(schemaId, credentialDefinitionId, keyProof, ret)
    handleError()

    return new ObjectHandle(ret.deref() as number)
  }

  public createCredentialRequest(options: {
    proverDid?: string
    credentialDefinition: ObjectHandle
    masterSecret: ObjectHandle
    masterSecretId: string
    credentialOffer: ObjectHandle
  }): { credentialRequest: ObjectHandle; credentialRequestMetadata: ObjectHandle } {
    const { proverDid, credentialDefinition, masterSecret, masterSecretId, credentialOffer } =
      serializeArguments(options)

    const credentialRequestPtr = allocatePointer()
    const credentialRequestMetadataPtr = allocatePointer()

    nativeAnoncreds.anoncreds_create_credential_request(
      proverDid,
      credentialDefinition,
      masterSecret,
      masterSecretId,
      credentialOffer,
      credentialRequestPtr,
      credentialRequestMetadataPtr
    )
    handleError()

    return {
      credentialRequest: new ObjectHandle(credentialRequestPtr.deref() as number),
      credentialRequestMetadata: new ObjectHandle(credentialRequestMetadataPtr.deref() as number),
    }
  }

  public createMasterSecret(): ObjectHandle {
    const ret = allocatePointer()

    nativeAnoncreds.anoncreds_create_master_secret(ret)
    handleError()

    return new ObjectHandle(ret.deref() as number)
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
    const { presentationRequest, masterSecret } = serializeArguments(options)

    const credentialEntries = options.credentials.map((value) => {
      const { credential, timestamp, revocationState: rev_state } = serializeArguments(value)
      return CredentialEntryStruct({ credential, timestamp, rev_state })
    })

    const credentialEntryList = CredentialEntryListStruct({
      count: credentialEntries.length,
      data: credentialEntries as unknown as TypedArray<
        StructObject<{
          credential: number
          timestamp: number
          rev_state: number
        }>
      >,
    })

    const credentialProves = options.credentialsProve.map((value) => {
      const { entryIndex: entry_idx, isPredicate: is_predicate, reveal, referent } = serializeArguments(value)

      return CredentialProveStruct({ entry_idx, referent, is_predicate, reveal })
    })

    const credentialProveList = CredentialProveListStruct({
      count: credentialProves.length,
      data: credentialProves as unknown as TypedArray<
        StructObject<{
          entry_idx: string | number
          referent: string
          is_predicate: number
          reveal: number
        }>
      >,
    })

    const selfAttestNames = StringListStruct({
      count: Object.keys(options.selfAttest).length,
      data: Object.keys(options.selfAttest) as unknown as TypedArray<string>,
    })

    const selfAttestValues = StringListStruct({
      count: Object.values(options.selfAttest).length,
      data: Object.values(options.selfAttest) as unknown as TypedArray<string>,
    })

    const schemaKeys = Object.keys(options.schemas)
    const schemaIds = StringListStruct({
      count: schemaKeys.length,
      data: schemaKeys as unknown as TypedArray<string>,
    })

    const schemaValues = Object.values(options.schemas)
    const schemas = ObjectHandleListStruct({
      count: schemaValues.length,
      data: ObjectHandleArray(schemaValues.map((o) => o.handle)),
    })

    const credentialDefinitionKeys = Object.keys(options.credentialDefinitions)
    const credentialDefinitionIds = StringListStruct({
      count: credentialDefinitionKeys.length,
      data: credentialDefinitionKeys as unknown as TypedArray<string>,
    })

    const credentialDefinitionValues = Object.values(options.credentialDefinitions)
    const credentialDefinitions = ObjectHandleListStruct({
      count: credentialDefinitionValues.length,
      data: ObjectHandleArray(credentialDefinitionValues.map((o) => o.handle)),
    })

    const ret = allocatePointer()

    nativeAnoncreds.anoncreds_create_presentation(
      presentationRequest,
      credentialEntryList as unknown as Buffer,
      credentialProveList as unknown as Buffer,
      selfAttestNames as unknown as Buffer,
      selfAttestValues as unknown as Buffer,
      masterSecret,
      schemas as unknown as Buffer,
      schemaIds as unknown as Buffer,
      credentialDefinitions as unknown as Buffer,
      credentialDefinitionIds as unknown as Buffer,
      ret
    )
    handleError()

    return new ObjectHandle(ret.deref() as number)
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
      credentialDefinitionIds,
    } = serializeArguments(options)

    const ret = allocateInt8Buffer()

    nativeAnoncreds.anoncreds_verify_presentation(
      presentation,
      presentationRequest,
      schemas,
      schemaIds,
      credentialDefinitions,
      credentialDefinitionIds,
      revocationRegistryDefinitions,
      revocationRegistryDefinitionIds,
      revocationStatusLists,
      ret
    )
    handleError()

    return Boolean(ret.deref() as number)
  }

  public createRevocationStatusList(options: {
    revocationRegistryDefinitionId: string
    revocationRegistryDefinition: ObjectHandle
    timestamp?: number
    issuanceByDefault: boolean
  }): ObjectHandle {
    const { timestamp, issuanceByDefault, revocationRegistryDefinition, revocationRegistryDefinitionId } =
      serializeArguments(options)

    const ret = allocatePointer()

    nativeAnoncreds.anoncreds_create_revocation_status_list(
      revocationRegistryDefinitionId,
      revocationRegistryDefinition,
      timestamp,
      issuanceByDefault,
      ret
    )
    handleError()

    return new ObjectHandle(ret.deref() as number)
  }

  public updateRevocationStatusListTimestampOnly(options: {
    timestamp: number
    currentRevocationStatusList: ObjectHandle
  }): ObjectHandle {
    const { currentRevocationStatusList, timestamp } = serializeArguments(options)
    const ret = allocatePointer()

    nativeAnoncreds.anoncreds_update_revocation_status_list_timestamp_only(timestamp, currentRevocationStatusList, ret)
    handleError()

    return new ObjectHandle(ret.deref() as number)
  }

  public updateRevocationStatusList(options: {
    timestamp?: number
    issued?: number[]
    revoked?: number[]
    revocationRegistryDefinition: ObjectHandle
    currentRevocationStatusList: ObjectHandle
  }): ObjectHandle {
    const { currentRevocationStatusList, timestamp, revocationRegistryDefinition, revoked, issued } =
      serializeArguments(options)
    const ret = allocatePointer()

    nativeAnoncreds.anoncreds_update_revocation_status_list(
      timestamp,
      issued,
      revoked,
      revocationRegistryDefinition,
      currentRevocationStatusList,
      ret
    )
    handleError()

    return new ObjectHandle(ret.deref() as number)
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
      tailsDirectoryPath,
    } = serializeArguments(options)

    const revocationRegistryDefinitionPtr = allocatePointer()
    const revocationRegistryDefinitionPrivate = allocatePointer()

    nativeAnoncreds.anoncreds_create_revocation_registry_def(
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
    handleError()

    return {
      revocationRegistryDefinition: new ObjectHandle(revocationRegistryDefinitionPtr.deref() as number),
      revocationRegistryDefinitionPrivate: new ObjectHandle(revocationRegistryDefinitionPrivate.deref() as number),
    }
  }

  public createOrUpdateRevocationState(options: {
    revocationRegistryDefinition: ObjectHandle
    revocationStatusList: ObjectHandle
    revocationRegistryIndex: number
    tailsPath: string
    previousRevocationStatusList?: ObjectHandle
    previousRevocationState?: ObjectHandle
  }): ObjectHandle {
    const { revocationRegistryDefinition, revocationStatusList, revocationRegistryIndex, tailsPath } =
      serializeArguments(options)

    const previousRevocationState = options.previousRevocationState ?? new ObjectHandle(0)
    const previousRevocationStatusList = options.previousRevocationStatusList ?? new ObjectHandle(0)
    const ret = allocatePointer()

    nativeAnoncreds.anoncreds_create_or_update_revocation_state(
      revocationRegistryDefinition,
      revocationStatusList,
      revocationRegistryIndex,
      tailsPath,
      previousRevocationStatusList.handle,
      previousRevocationState.handle,
      ret
    )
    handleError()

    return new ObjectHandle(ret.deref() as number)
  }
  public version(): string {
    return nativeAnoncreds.anoncreds_version()
  }

  // This should be called when a function returns a non-zero code
  public getCurrentError(): string {
    const ret = allocateStringBuffer()
    nativeAnoncreds.anoncreds_get_current_error(ret)
    handleError()

    return ret.deref() as string
  }

  private objectFromJson(method: (byteBuffer: Buffer, ret: Buffer) => unknown, options: { json: string }) {
    const ret = allocatePointer()

    const byteBuffer = ByteBuffer.fromUint8Array(new TextEncoder().encode(options.json))
    handleError()

    method(byteBuffer as unknown as Buffer, ret)

    return new ObjectHandle(ret.deref() as number)
  }

  public presentationRequestFromJson(options: { json: string }) {
    return this.objectFromJson(nativeAnoncreds.anoncreds_presentation_request_from_json, options)
  }

  public masterSecretFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(nativeAnoncreds.anoncreds_master_secret_from_json, options)
  }

  public credentialRequestFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(nativeAnoncreds.anoncreds_credential_request_from_json, options)
  }

  public credentialRequestMetadataFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(nativeAnoncreds.anoncreds_credential_request_metadata_from_json, options)
  }

  public revocationRegistryDefinitionFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(nativeAnoncreds.anoncreds_revocation_registry_definition_from_json, options)
  }

  public revocationRegistryFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(nativeAnoncreds.anoncreds_revocation_registry_from_json, options)
  }

  public revocationStateFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(nativeAnoncreds.anoncreds_revocation_state_from_json, options)
  }

  public presentationFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(nativeAnoncreds.anoncreds_presentation_from_json, options)
  }

  public credentialOfferFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(nativeAnoncreds.anoncreds_credential_offer_from_json, options)
  }

  public schemaFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(nativeAnoncreds.anoncreds_schema_from_json, options)
  }

  public credentialFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(nativeAnoncreds.anoncreds_credential_from_json, options)
  }

  public revocationRegistryDefinitionPrivateFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(nativeAnoncreds.anoncreds_revocation_registry_definition_private_from_json, options)
  }

  public revocationRegistryDeltaFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(nativeAnoncreds.anoncreds_revocation_registry_delta_from_json, options)
  }

  public credentialDefinitionFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(nativeAnoncreds.anoncreds_credential_definition_from_json, options)
  }

  public credentialDefinitionPrivateFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(nativeAnoncreds.anoncreds_credential_definition_private_from_json, options)
  }

  public keyCorrectnessProofFromJson(options: { json: string }): ObjectHandle {
    return this.objectFromJson(nativeAnoncreds.anoncreds_key_correctness_proof_from_json, options)
  }

  public getJson(options: { objectHandle: ObjectHandle }) {
    const ret = allocateByteBuffer()

    const { objectHandle } = serializeArguments(options)
    nativeAnoncreds.anoncreds_object_get_json(objectHandle, ret)
    handleError()

    const output = new Uint8Array(byteBufferToBuffer(ret.deref() as { data: Buffer; len: number }))

    return new TextDecoder().decode(output)
  }

  public getTypeName(options: { objectHandle: ObjectHandle }) {
    const { objectHandle } = serializeArguments(options)

    const ret = allocateStringBuffer()

    nativeAnoncreds.anoncreds_object_get_type_name(objectHandle, ret)
    handleError()

    return ret.deref() as string
  }

  public objectFree(options: { objectHandle: ObjectHandle }) {
    nativeAnoncreds.anoncreds_object_free(options.objectHandle.handle)
    handleError()
  }
}
