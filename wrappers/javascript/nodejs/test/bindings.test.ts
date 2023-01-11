import { anoncreds } from 'anoncreds-shared'

import { setup } from './utils'

// FIXTURES
const TEST_DID = '55GkHamhTU1ZbTbV2ab9DE'
const TEST_SCHEMA = '55GkHamhTU1ZbTbV2ab9DE:2:schema-1:1'

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
    const schemaObj = anoncreds.createSchema({
      name: 'schema-1',
      originDid: TEST_DID,
      version: '1',
      sequenceNumber: 1,
      attributeNames: ['attr-1'],
    })

    const schemaId = anoncreds.schemaGetAttribute({
      objectHandle: schemaObj,
      name: 'id',
    })

    expect(schemaId).toEqual(TEST_SCHEMA)

    const json = anoncreds.getJson({ objectHandle: schemaObj })
    expect(JSON.parse(json)).toEqual({
      id: TEST_SCHEMA,
      name: 'schema-1',
      ver: '1.0',
      seqNo: 1,
      version: '1',
      attrNames: ['attr-1'],
    })
  })

  test('create credential definition', () => {
    const schemaObj = anoncreds.createSchema({
      name: 'schema-1',
      originDid: TEST_DID,
      version: '1',
      sequenceNumber: 1,
      attributeNames: ['attr-1'],
    })

    const { keyProof, credentialDefinition, credentialDefinitionPrivate } = anoncreds.createCredentialDefinition({
      originDid: TEST_DID,
      schema: schemaObj,
      signatureType: 'CL',
      supportRevocation: true,
      tag: 'TAG',
    })

    const credDefJson = anoncreds.getJson({ objectHandle: credentialDefinition })
    expect(JSON.parse(credDefJson)).toEqual(
      expect.objectContaining({
        id: '55GkHamhTU1ZbTbV2ab9DE:3:CL:1:TAG',
        tag: 'TAG',
        type: 'CL',
        schemaId: '1',
        ver: '1.0',
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
  }),
    test('create revocation registry', () => {
      const schemaObj = anoncreds.createSchema({
        name: 'schema-1',
        originDid: TEST_DID,
        version: '1',
        sequenceNumber: 1,
        attributeNames: ['attr-1'],
      })

      const { credentialDefinition } = anoncreds.createCredentialDefinition({
        originDid: TEST_DID,
        schema: schemaObj,
        signatureType: 'CL',
        supportRevocation: true,
        tag: 'TAG',
      })
      const { registryDefinition } = anoncreds.createRevocationRegistry({
        originDid: TEST_DID,
        credentialDefinition,
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
          credDefId: '55GkHamhTU1ZbTbV2ab9DE:3:CL:1:TAG',
          id: '55GkHamhTU1ZbTbV2ab9DE:4:55GkHamhTU1ZbTbV2ab9DE:3:CL:1:TAG:CL_ACCUM:default',
          revocDefType: 'CL_ACCUM',
          tag: 'default',
        })
      )

      expect(JSON.parse(json).value).toEqual(
        expect.objectContaining({
          issuanceType: 'ISSUANCE_BY_DEFAULT',
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
      originDid: TEST_DID,
      version: '1',
      sequenceNumber: 1,
      attributeNames: ['attr-1'],
    })

    const { credentialDefinition, keyProof } = anoncreds.createCredentialDefinition({
      originDid: TEST_DID,
      schema: schemaObj,
      signatureType: 'CL',
      supportRevocation: true,
      tag: 'TAG',
    })

    const credOfferObj = anoncreds.createCredentialOffer({
      schemaId: TEST_SCHEMA,
      credentialDefinition: credentialDefinition,
      keyProof,
    })

    const json = anoncreds.getJson({ objectHandle: credOfferObj })
    expect(JSON.parse(json)).toEqual(
      expect.objectContaining({
        cred_def_id: '55GkHamhTU1ZbTbV2ab9DE:3:CL:1:TAG',
        schema_id: TEST_SCHEMA,
      })
    )
    expect(JSON.parse(json)).toHaveProperty('nonce')
    expect(JSON.parse(json)).toHaveProperty('key_correctness_proof')
  })

  test('create credential request', () => {
    const schemaObj = anoncreds.createSchema({
      name: 'schema-1',
      originDid: TEST_DID,
      version: '1',
      sequenceNumber: 1,
      attributeNames: ['attr-1'],
    })

    const { credentialDefinition, keyProof } = anoncreds.createCredentialDefinition({
      originDid: TEST_DID,
      schema: schemaObj,
      signatureType: 'CL',
      supportRevocation: true,
      tag: 'TAG',
    })

    const credOfferObj = anoncreds.createCredentialOffer({
      schemaId: TEST_SCHEMA,
      credentialDefinition: credentialDefinition,
      keyProof,
    })

    const masterSecret = anoncreds.createMasterSecret()
    const masterSecretId = 'master secret id'

    const { credentialRequest, credentialRequestMeta } = anoncreds.createCredentialRequest({
      proverDid: TEST_DID,
      credentialDefinition: credentialDefinition,
      masterSecret,
      masterSecretId,
      credentialOffer: credOfferObj,
    })

    const credReqJson = anoncreds.getJson({ objectHandle: credentialRequest })
    expect(JSON.parse(credReqJson)).toEqual(
      expect.objectContaining({
        prover_did: TEST_DID,
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
      originDid: TEST_DID,
      version: '1',
      sequenceNumber: 1,
      attributeNames: ['attr-1'],
    })

    const { credentialDefinition, keyProof, credentialDefinitionPrivate } = anoncreds.createCredentialDefinition({
      originDid: TEST_DID,
      schema: schemaObj,
      signatureType: 'CL',
      supportRevocation: true,
      tag: 'TAG',
    })

    const credOfferObj = anoncreds.createCredentialOffer({
      schemaId: TEST_SCHEMA,
      credentialDefinition: credentialDefinition,
      keyProof,
    })

    const masterSecret = anoncreds.createMasterSecret()
    const masterSecretId = 'master secret id'

    const { credentialRequestMeta, credentialRequest } = anoncreds.createCredentialRequest({
      proverDid: TEST_DID,
      credentialDefinition,
      masterSecret,
      masterSecretId,
      credentialOffer: credOfferObj,
    })

    const { registryDefinition, registryEntry, registryDefinitionPrivate } = anoncreds.createRevocationRegistry({
      originDid: TEST_DID,
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
      credentialDefinition: credentialDefinition,
      credentialDefinitionPrivate: credentialDefinitionPrivate,
      credentialOffer: credOfferObj,
      credentialRequest: credentialRequest,
      attributeRawValues: { 'attr-1': 'test' },
      attributeEncodedValues: undefined,
      revocationConfiguration: {
        registryDefinition,
        registryDefinitionPrivate,
        registry: registryEntry,
        registryIndex: 1,
        tailsPath: tailsPath,
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
        cred_def_id: '55GkHamhTU1ZbTbV2ab9DE:3:CL:1:TAG',
        rev_reg_id: '55GkHamhTU1ZbTbV2ab9DE:4:55GkHamhTU1ZbTbV2ab9DE:3:CL:1:TAG:CL_ACCUM:default',
        schema_id: TEST_SCHEMA,
      })
    )

    const credReceivedJson = anoncreds.getJson({ objectHandle: credReceived })
    expect(JSON.parse(credReceivedJson)).toEqual(
      expect.objectContaining({
        cred_def_id: '55GkHamhTU1ZbTbV2ab9DE:3:CL:1:TAG',
        rev_reg_id: '55GkHamhTU1ZbTbV2ab9DE:4:55GkHamhTU1ZbTbV2ab9DE:3:CL:1:TAG:CL_ACCUM:default',
        schema_id: TEST_SCHEMA,
      })
    )
    expect(JSON.parse(credReceivedJson)).toHaveProperty('signature')
    expect(JSON.parse(credReceivedJson)).toHaveProperty('witness')
  })

  test('create and verify presentation', () => {
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
      originDid: TEST_DID,
      version: '1',
      sequenceNumber: 1,
      attributeNames: ['attr-1'],
    })

    const { credentialDefinition, credentialDefinitionPrivate, keyProof } = anoncreds.createCredentialDefinition({
      originDid: TEST_DID,
      schema: schemaObj,
      signatureType: 'CL',
      supportRevocation: true,
      tag: 'TAG',
    })

    const credOfferObj = anoncreds.createCredentialOffer({
      schemaId: TEST_SCHEMA,
      credentialDefinition,
      keyProof,
    })

    const masterSecret = anoncreds.createMasterSecret()
    const masterSecretId = 'master secret id'

    const { credentialRequest, credentialRequestMeta } = anoncreds.createCredentialRequest({
      proverDid: TEST_DID,
      credentialDefinition,
      masterSecret,
      masterSecretId,
      credentialOffer: credOfferObj,
    })

    const { registryDefinition, registryEntry, registryDefinitionPrivate, registryInitDelta } =
      anoncreds.createRevocationRegistry({
        originDid: TEST_DID,
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
      revocationRegistryDelta: registryInitDelta,
      revocationRegistryIndex,
      timestamp,
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
