import { anoncreds } from 'anoncreds-shared'

import { setup } from './utils'

describe('bindings', () => {
  beforeAll(() => setup())

  test('version', () => {
    const version = anoncreds.version()

    expect(version).toEqual('0.3.1')
  })

  test('current error', () => {
    const error = anoncreds.getCurrentError()

    expect(JSON.parse(error)).toEqual({ code: 0, message: null })
  })

  test('generate nonce', () => {
    const nonce = anoncreds.generateNonce()
    expect(nonce).toMatch(/^\d*$/)
  })

  test('create schema', () => {
    const obj = {
      name: 'schema-1',
      issuerId: 'mock:uri',
      version: '1',
      attributeNames: ['attr-1'],
    }
    const schemaObj = anoncreds.createSchema(obj)

    const json = anoncreds.getJson({ objectHandle: schemaObj })

    expect(JSON.parse(json)).toEqual({
      name: 'schema-1',
      version: '1',
      issuerId: 'mock:uri',
      attrNames: ['attr-1'],
    })
  })

  test('create credential definition', () => {
    const schemaObj = anoncreds.createSchema({
      name: 'schema-1',
      issuerId: 'mock:uri',
      version: '1',
      attributeNames: ['attr-1'],
    })

    const { keyProof, credentialDefinition, credentialDefinitionPrivate } = anoncreds.createCredentialDefinition({
      schemaId: 'mock:uri',
      issuerId: 'mock:uri',
      schema: schemaObj,
      signatureType: 'CL',
      supportRevocation: true,
      tag: 'TAG',
    })

    const credDefJson = anoncreds.getJson({ objectHandle: credentialDefinition })
    expect(JSON.parse(credDefJson)).toEqual(
      expect.objectContaining({
        tag: 'TAG',
        type: 'CL',
        schemaId: 'mock:uri',
        issuerId: 'mock:uri',
      })
    )

    const credDefPvtJson = anoncreds.getJson({ objectHandle: credentialDefinitionPrivate })
    expect(JSON.parse(credDefPvtJson)).toHaveProperty('value')

    const keyProofJson = anoncreds.getJson({ objectHandle: keyProof })
    expect(JSON.parse(keyProofJson)).toHaveProperty('c')
    expect(JSON.parse(keyProofJson)).toHaveProperty('xr_cap')
  })

  test('encode credential attributes', () => {
    const encoded = anoncreds.encodeCredentialAttributes({ attributeRawValues: ['value2', 'value1'] })

    expect(encoded).toEqual(
      expect.arrayContaining([
        '2360207505573967335061705667247358223962382058438765247085581582985596391831',
        '27404702143883897701950953229849815393032792099783647152371385368148256400014',
      ])
    )
  })

  test('create revocation registry', () => {
    const schemaObj = anoncreds.createSchema({
      name: 'schema-1',
      issuerId: 'mock:uri',
      version: '1',
      sequenceNumber: 1,
      attributeNames: ['attr-1'],
    })

    const { credentialDefinition } = anoncreds.createCredentialDefinition({
      schemaId: 'mock:uri',
      issuerId: 'mock:uri',
      schema: schemaObj,
      signatureType: 'CL',
      supportRevocation: true,
      tag: 'TAG',
    })

    const { registryDefinition } = anoncreds.createRevocationRegistry({
      credentialDefinitionId: 'mock:uri',
      credentialDefinition,
      issuerId: 'mock:uri',
      tag: 'default',
      revocationRegistryType: 'CL_ACCUM',
      maximumCredentialNumber: 100,
    })

    const maximumCredentialNumber = anoncreds.revocationRegistryDefinitionGetAttribute({
      objectHandle: registryDefinition,
      name: 'max_cred_num',
    })

    expect(maximumCredentialNumber).toEqual('100')
    const json = anoncreds.getJson({ objectHandle: registryDefinition })
    expect(JSON.parse(json)).toEqual(
      expect.objectContaining({
        credDefId: 'mock:uri',
        revocDefType: 'CL_ACCUM',
        tag: 'default',
      })
    )

    expect(JSON.parse(json).value).toEqual(
      expect.objectContaining({
        maxCredNum: 100,
      })
    )
  })

  test('create master secret', () => {
    const masterSecret = anoncreds.createMasterSecret()
    const json = anoncreds.getJson({ objectHandle: masterSecret })
    expect(JSON.parse(json)).toHaveProperty('value')
    expect(JSON.parse(json).value).toHaveProperty('ms')
  })

  test('create credential offer', () => {
    const schemaObj = anoncreds.createSchema({
      name: 'schema-1',
      issuerId: 'mock:uri',
      version: '1',
      sequenceNumber: 1,
      attributeNames: ['attr-1'],
    })

    const { keyProof } = anoncreds.createCredentialDefinition({
      schemaId: 'mock:uri',
      schema: schemaObj,
      issuerId: 'mock:uri',
      signatureType: 'CL',
      supportRevocation: true,
      tag: 'TAG',
    })

    const credOfferObj = anoncreds.createCredentialOffer({
      schemaId: 'mock:uri',
      credentialDefinitionId: 'mock:uri',
      keyProof,
    })

    const json = anoncreds.getJson({ objectHandle: credOfferObj })
    expect(JSON.parse(json)).toEqual(
      expect.objectContaining({
        cred_def_id: 'mock:uri',
        schema_id: 'mock:uri',
      })
    )
    expect(JSON.parse(json)).toHaveProperty('nonce')
    expect(JSON.parse(json)).toHaveProperty('key_correctness_proof')
  })

  test('create credential request', () => {
    const schemaObj = anoncreds.createSchema({
      name: 'schema-1',
      issuerId: 'mock:uri',
      version: '1',
      sequenceNumber: 1,
      attributeNames: ['attr-1'],
    })

    const { credentialDefinition, keyProof } = anoncreds.createCredentialDefinition({
      schemaId: 'mock:uri',
      issuerId: 'mock:uri',
      schema: schemaObj,
      signatureType: 'CL',
      supportRevocation: true,
      tag: 'TAG',
    })

    const credOfferObj = anoncreds.createCredentialOffer({
      schemaId: 'mock:uri',
      credentialDefinitionId: 'mock:uri',
      keyProof,
    })

    const masterSecret = anoncreds.createMasterSecret()
    const masterSecretId = 'master secret id'

    const { credentialRequest, credentialRequestMeta } = anoncreds.createCredentialRequest({
      credentialDefinition: credentialDefinition,
      masterSecret,
      masterSecretId,
      credentialOffer: credOfferObj,
    })

    const credReqJson = anoncreds.getJson({ objectHandle: credentialRequest })
    expect(JSON.parse(credReqJson)).toEqual(
      expect.objectContaining({
        cred_def_id: 'mock:uri',
      })
    )
    expect(JSON.parse(credReqJson)).toHaveProperty('blinded_ms')
    expect(JSON.parse(credReqJson)).toHaveProperty('nonce')

    const credReqMetadataJson = anoncreds.getJson({ objectHandle: credentialRequestMeta })
    expect(JSON.parse(credReqMetadataJson)).toEqual(
      expect.objectContaining({
        master_secret_name: masterSecretId,
      })
    )
    expect(JSON.parse(credReqMetadataJson)).toHaveProperty('master_secret_blinding_data')
    expect(JSON.parse(credReqMetadataJson)).toHaveProperty('nonce')
  })

  test('create and receive credential', () => {
    const schemaObj = anoncreds.createSchema({
      name: 'schema-1',
      issuerId: 'mock:uri',
      version: '1',
      sequenceNumber: 1,
      attributeNames: ['attr-1'],
    })

    const { credentialDefinition, keyProof, credentialDefinitionPrivate } = anoncreds.createCredentialDefinition({
      schemaId: 'mock:uri',
      issuerId: 'mock:uri',
      schema: schemaObj,
      signatureType: 'CL',
      supportRevocation: true,
      tag: 'TAG',
    })

    const credOfferObj = anoncreds.createCredentialOffer({
      schemaId: 'mock:uri',
      credentialDefinitionId: 'mock:uri',
      keyProof,
    })

    const masterSecret = anoncreds.createMasterSecret()
    const masterSecretId = 'master secret id'

    const { credentialRequestMeta, credentialRequest } = anoncreds.createCredentialRequest({
      credentialDefinition,
      masterSecret,
      masterSecretId,
      credentialOffer: credOfferObj,
    })

    const { registryDefinition, registryDefinitionPrivate } = anoncreds.createRevocationRegistry({
      credentialDefinitionId: 'mock:uri',
      credentialDefinition,
      issuerId: 'mock:uri',
      tag: 'default',
      revocationRegistryType: 'CL_ACCUM',
      maximumCredentialNumber: 100,
    })

    const tailsPath = anoncreds.revocationRegistryDefinitionGetAttribute({
      objectHandle: registryDefinition,
      name: 'tails_location',
    })

    const { credential } = anoncreds.createCredential({
      credentialDefinition,
      credentialDefinitionPrivate,
      credentialOffer: credOfferObj,
      credentialRequest: credentialRequest,
      attributeRawValues: { 'attr-1': 'test' },
      revocationRegistryId: 'mock:uri',
      revocationConfiguration: {
        registryDefinition,
        registryDefinitionPrivate,
        registry: registryEntry,
        registryIndex: 1,
        tailsPath,
      },
    })

    const credReceived = anoncreds.processCredential({
      credential,
      credentialDefinition,
      credentialRequestMetadata: credentialRequestMeta,
      masterSecret,
      revocationRegistryDefinition: registryDefinition,
    })

    const credJson = anoncreds.getJson({ objectHandle: credential })
    expect(JSON.parse(credJson)).toEqual(
      expect.objectContaining({
        cred_def_id: 'mock:uri',
        rev_reg_id: 'mock:uri',
        schema_id: 'mock:uri',
      })
    )

    const credReceivedJson = anoncreds.getJson({ objectHandle: credReceived })
    expect(JSON.parse(credReceivedJson)).toEqual(
      expect.objectContaining({
        cred_def_id: 'mock:uri',
        rev_reg_id: 'mock:uri',
        schema_id: 'mock:uri',
      })
    )
    expect(JSON.parse(credReceivedJson)).toHaveProperty('signature')
    expect(JSON.parse(credReceivedJson)).toHaveProperty('witness')
  })

  // Skip this for now as there are some ffi issues with revocation
  xtest('create and verify presentation', () => {
    const timestamp = Math.floor(Date.now() / 1000)
    const nonce = anoncreds.generateNonce()

    const presRequestObj = anoncreds.presentationRequestFromJson({
      json: JSON.stringify({
        name: 'proof',
        version: '1.0',
        nonce,
        requested_attributes: {
          reft: {
            name: 'attr-1',
            non_revoked: { from: timestamp, to: timestamp },
          },
          name: {
            name: 'name',
            non_revoked: { from: timestamp, to: timestamp },
          },
        },
        requested_predicates: {},
        non_revoked: { from: timestamp, to: timestamp },
        ver: '1.0',
      }),
    })

    expect(anoncreds.getTypeName({ objectHandle: presRequestObj })).toEqual('PresentationRequest')

    const schemaObj = anoncreds.createSchema({
      name: 'schema-1',
      issuerId: 'mock:uri',
      version: '1',
      sequenceNumber: 1,
      attributeNames: ['attr-1'],
    })

    const { credentialDefinition, credentialDefinitionPrivate, keyProof } = anoncreds.createCredentialDefinition({
      schemaId: 'mock:uri',
      issuerId: 'mock:uri',
      schema: schemaObj,
      signatureType: 'CL',
      supportRevocation: true,
      tag: 'TAG',
    })

    const credOfferObj = anoncreds.createCredentialOffer({
      schemaId: 'mock:uri',
      credentialDefinitionId: 'mock:uri',
      keyProof,
    })

    const masterSecret = anoncreds.createMasterSecret()
    const masterSecretId = 'master secret id'

    const { credentialRequest, credentialRequestMeta } = anoncreds.createCredentialRequest({
      credentialDefinition,
      masterSecret,
      masterSecretId,
      credentialOffer: credOfferObj,
    })

    const { registryDefinition, registryEntry, registryDefinitionPrivate, registryInitDelta } =
      anoncreds.createRevocationRegistry({
        credentialDefinitionId: 'mock:uri',
        credentialDefinition,
        tag: 'default',
        revocationRegistryType: 'CL_ACCUM',
        maximumCredentialNumber: 100,
      })

    const tailsPath = anoncreds.revocationRegistryDefinitionGetAttribute({
      objectHandle: registryDefinition,
      name: 'tails_location',
    })

    const { credential } = anoncreds.createCredential({
      credentialDefinition,
      credentialDefinitionPrivate,
      credentialOffer: credOfferObj,
      credentialRequest,
      attributeRawValues: { 'attr-1': 'test' },
      attributeEncodedValues: undefined,
      revocationRegistryId: 'mock:uri',
      revocationConfiguration: {
        registryDefinition,
        registryDefinitionPrivate,
        registry: registryEntry,
        registryIndex: 1,
        tailsPath: tailsPath,
      },
    })

    const credentialReceived = anoncreds.processCredential({
      credential,
      credentialDefinition,
      credentialRequestMetadata: credentialRequestMeta,
      masterSecret,
      revocationRegistryDefinition: registryDefinition,
    })

    const revRegIndex = anoncreds.credentialGetAttribute({
      objectHandle: credentialReceived,
      name: 'rev_reg_index',
    })

    const revocationRegistryIndex = revRegIndex === null ? 0 : parseInt(revRegIndex)

    const revocationState = anoncreds.createOrUpdateRevocationState({
      revocationRegistryDefinition: registryDefinition,
      revocationRegistryList: registryInitDelta,
      revocationRegistryIndex,
      tailsPath,
    })

    const presentationObj = anoncreds.createPresentation({
      presentationRequest: presRequestObj,
      credentials: [
        {
          credential: credentialReceived,
          revocationState,
          timestamp,
        },
      ],
      credentialDefinitions: [credentialDefinition],
      credentialsProve: [
        {
          entryIndex: 0,
          isPredicate: false,
          referent: 'reft',
          reveal: true,
        },
      ],
      masterSecret,
      schemas: [schemaObj],
      selfAttest: { name: 'value' },
    })

    const verify = anoncreds.verifyPresentation({
      presentation: presentationObj,
      presentationRequest: presRequestObj,
      credentialDefinitions: [credentialDefinition],
      revocationRegistryDefinitions: [registryDefinition],
      revocationEntries: [
        {
          entry: registryEntry,
          revocationRegistryDefinitionEntryIndex: 0,
          timestamp,
        },
      ],
      schemas: [schemaObj],
    })

    expect(verify).toBeTruthy()
  })
})
