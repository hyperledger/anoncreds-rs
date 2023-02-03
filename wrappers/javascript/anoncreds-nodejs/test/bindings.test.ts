import { anoncreds } from '@hyperledger/anoncreds-shared'

import { setup } from './utils'

describe('bindings', () => {
  beforeAll(() => setup())

  test('version', () => {
    const version = anoncreds.version()

    expect(version).toEqual('0.1.0-dev.4')
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

    const { revocationRegistryDefinition } = anoncreds.createRevocationRegistryDefinition({
      credentialDefinitionId: 'mock:uri',
      credentialDefinition,
      issuerId: 'mock:uri',
      tag: 'default',
      revocationRegistryType: 'CL_ACCUM',
      maximumCredentialNumber: 100,
    })

    const maximumCredentialNumber = anoncreds.revocationRegistryDefinitionGetAttribute({
      objectHandle: revocationRegistryDefinition,
      name: 'max_cred_num',
    })

    expect(maximumCredentialNumber).toEqual('100')
    const json = anoncreds.getJson({ objectHandle: revocationRegistryDefinition })
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

    const { credentialRequest, credentialRequestMetadata } = anoncreds.createCredentialRequest({
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

    const credReqMetadataJson = anoncreds.getJson({ objectHandle: credentialRequestMetadata })
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

    const { revocationRegistryDefinition, revocationRegistryDefinitionPrivate } =
      anoncreds.createRevocationRegistryDefinition({
        credentialDefinitionId: 'mock:uri',
        credentialDefinition,
        issuerId: 'mock:uri',
        tag: 'some_tag',
        revocationRegistryType: 'CL_ACCUM',
        maximumCredentialNumber: 10,
      })

    const tailsPath = anoncreds.revocationRegistryDefinitionGetAttribute({
      objectHandle: revocationRegistryDefinition,
      name: 'tails_location',
    })

    const timeCreateRevStatusList = 12
    const revocationStatusList = anoncreds.createRevocationStatusList({
      timestamp: timeCreateRevStatusList,
      issuanceByDefault: true,
      revocationRegistryDefinition,
      revocationRegistryDefinitionId: 'mock:uri',
    })

    const credentialOffer = anoncreds.createCredentialOffer({
      schemaId: 'mock:uri',
      credentialDefinitionId: 'mock:uri',
      keyProof,
    })

    const masterSecret = anoncreds.createMasterSecret()
    const masterSecretId = 'master secret id'

    const { credentialRequestMetadata, credentialRequest } = anoncreds.createCredentialRequest({
      credentialDefinition,
      masterSecret,
      masterSecretId,
      credentialOffer,
    })

    const credential = anoncreds.createCredential({
      credentialDefinition,
      credentialDefinitionPrivate,
      credentialOffer,
      credentialRequest,
      attributeRawValues: { 'attr-1': 'test' },
      revocationRegistryId: 'mock:uri',
      revocationStatusList,
      revocationConfiguration: {
        revocationRegistryDefinition,
        revocationRegistryDefinitionPrivate,
        registryIndex: 9,
        tailsPath,
      },
    })

    const credReceived = anoncreds.processCredential({
      credential,
      credentialDefinition,
      credentialRequestMetadata,
      masterSecret,
      revocationRegistryDefinition,
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

  test('create and verify presentation', () => {
    const nonce = anoncreds.generateNonce()

    const presentationRequest = anoncreds.presentationRequestFromJson({
      json: JSON.stringify({
        nonce,
        name: 'pres_req_1',
        version: '0.1',
        requested_attributes: {
          attr1_referent: {
            name: 'name',
            issuer: 'mock:uri',
          },
          attr2_referent: {
            name: 'sex',
          },
          attr3_referent: {
            name: 'phone',
          },
          attr4_referent: {
            names: ['name', 'height'],
          },
        },
        requested_predicates: {
          predicate1_referent: { name: 'age', p_type: '>=', p_value: 18 },
        },
        non_revoked: { from: 10, to: 200 },
      }),
    })

    expect(anoncreds.getTypeName({ objectHandle: presentationRequest })).toEqual('PresentationRequest')

    const schemaObj = anoncreds.createSchema({
      name: 'schema-1',
      issuerId: 'mock:uri',
      version: '1',
      attributeNames: ['name', 'age', 'sex', 'height'],
    })

    const { credentialDefinition, keyProof, credentialDefinitionPrivate } = anoncreds.createCredentialDefinition({
      schemaId: 'mock:uri',
      issuerId: 'mock:uri',
      schema: schemaObj,
      signatureType: 'CL',
      supportRevocation: true,
      tag: 'TAG',
    })

    const { revocationRegistryDefinition, revocationRegistryDefinitionPrivate } =
      anoncreds.createRevocationRegistryDefinition({
        credentialDefinitionId: 'mock:uri',
        credentialDefinition,
        issuerId: 'mock:uri',
        tag: 'some_tag',
        revocationRegistryType: 'CL_ACCUM',
        maximumCredentialNumber: 10,
      })

    const tailsPath = anoncreds.revocationRegistryDefinitionGetAttribute({
      objectHandle: revocationRegistryDefinition,
      name: 'tails_location',
    })

    const timeCreateRevStatusList = 12
    const revocationStatusList = anoncreds.createRevocationStatusList({
      timestamp: timeCreateRevStatusList,
      issuanceByDefault: true,
      revocationRegistryDefinition,
      revocationRegistryDefinitionId: 'mock:uri',
    })

    const credentialOffer = anoncreds.createCredentialOffer({
      schemaId: 'mock:uri',
      credentialDefinitionId: 'mock:uri',
      keyProof,
    })

    const masterSecret = anoncreds.createMasterSecret()
    const masterSecretId = 'master secret id'

    const { credentialRequestMetadata, credentialRequest } = anoncreds.createCredentialRequest({
      credentialDefinition,
      masterSecret,
      masterSecretId,
      credentialOffer,
    })

    const credential = anoncreds.createCredential({
      credentialDefinition,
      credentialDefinitionPrivate,
      credentialOffer,
      credentialRequest,
      attributeRawValues: { name: 'Alex', height: '175', age: '28', sex: 'male' },
      revocationRegistryId: 'mock:uri',
      revocationStatusList,
      revocationConfiguration: {
        revocationRegistryDefinition,
        revocationRegistryDefinitionPrivate,
        registryIndex: 9,
        tailsPath,
      },
    })

    const credentialReceived = anoncreds.processCredential({
      credential,
      credentialDefinition,
      credentialRequestMetadata,
      masterSecret,
      revocationRegistryDefinition,
    })

    const revRegIndex = anoncreds.credentialGetAttribute({
      objectHandle: credentialReceived,
      name: 'rev_reg_index',
    })

    const revocationRegistryIndex = revRegIndex === null ? 0 : parseInt(revRegIndex)

    const revocationState = anoncreds.createOrUpdateRevocationState({
      revocationRegistryDefinition,
      revocationStatusList,
      revocationRegistryIndex,
      tailsPath,
    })

    const presentation = anoncreds.createPresentation({
      presentationRequest,
      credentials: [
        {
          credential: credentialReceived,
          revocationState,
          timestamp: timeCreateRevStatusList,
        },
      ],
      credentialDefinitions: { 'mock:uri': credentialDefinition },
      credentialsProve: [
        {
          entryIndex: 0,
          isPredicate: false,
          referent: 'attr1_referent',
          reveal: true,
        },
        {
          entryIndex: 0,
          isPredicate: false,
          referent: 'attr2_referent',
          reveal: false,
        },
        {
          entryIndex: 0,
          isPredicate: false,
          referent: 'attr4_referent',
          reveal: true,
        },
        {
          entryIndex: 0,
          isPredicate: true,
          referent: 'predicate1_referent',
          reveal: true,
        },
      ],
      masterSecret,
      schemas: { 'mock:uri': schemaObj },
      selfAttest: { attr3_referent: '8-800-300' },
    })

    expect(presentation.handle).toStrictEqual(expect.any(Number))

    const verify = anoncreds.verifyPresentation({
      presentation,
      presentationRequest,
      schemas: [schemaObj],
      schemaIds: ['mock:uri'],
      credentialDefinitions: [credentialDefinition],
      credentialDefinitionIds: ['mock:uri'],
      revocationRegistryDefinitions: [revocationRegistryDefinition],
      revocationRegistryDefinitionIds: ['mock:uri'],
      revocationStatusLists: [revocationStatusList],
    })

    expect(verify).toBeTruthy()
  })
})
