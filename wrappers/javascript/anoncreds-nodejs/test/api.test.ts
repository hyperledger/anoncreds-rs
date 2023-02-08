import {
  anoncreds,
  Credential,
  CredentialDefinition,
  CredentialOffer,
  CredentialRequest,
  CredentialRevocationConfig,
  CredentialRevocationState,
  MasterSecret,
  Presentation,
  PresentationRequest,
  RevocationRegistryDefinition,
  RevocationStatusList,
  Schema,
} from '@hyperledger/anoncreds-shared'

import { setup } from './utils'

describe('API', () => {
  beforeAll(() => setup())

  test('create and verify presentation', () => {
    const nonce = anoncreds.generateNonce()

    const presentationRequest = PresentationRequest.load(
      JSON.stringify({
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
      })
    )

    const schema = Schema.create({
      name: 'schema-1',
      issuerId: 'mock:uri',
      version: '1',
      attributeNames: ['name', 'age', 'sex', 'height'],
    })

    const { credentialDefinition, keyCorrectnessProof, credentialDefinitionPrivate } = CredentialDefinition.create({
      schemaId: 'mock:uri',
      issuerId: 'mock:uri',
      schema,
      signatureType: 'CL',
      supportRevocation: true,
      tag: 'TAG',
    })

    const { revocationRegistryDefinition, revocationRegistryDefinitionPrivate } = RevocationRegistryDefinition.create({
      credentialDefinitionId: 'mock:uri',
      credentialDefinition,
      issuerId: 'mock:uri',
      tag: 'some_tag',
      revocationRegistryType: 'CL_ACCUM',
      maximumCredentialNumber: 10,
    })

    const tailsPath = revocationRegistryDefinition.getTailsLocation()

    const timeCreateRevStatusList = 12
    const revocationStatusList = RevocationStatusList.create({
      timestamp: timeCreateRevStatusList,
      issuanceByDefault: true,
      revocationRegistryDefinition,
      revocationRegistryDefinitionId: 'mock:uri',
    })

    const credentialOffer = CredentialOffer.create({
      schemaId: 'mock:uri',
      credentialDefinitionId: 'mock:uri',
      keyCorrectnessProof,
    })

    const masterSecret = MasterSecret.create()
    const masterSecretId = 'master secret id'

    const { credentialRequestMetadata, credentialRequest } = CredentialRequest.create({
      credentialDefinition,
      masterSecret,
      masterSecretId,
      credentialOffer,
    })

    const credential = Credential.create({
      credentialDefinition,
      credentialDefinitionPrivate,
      credentialOffer,
      credentialRequest,
      attributeRawValues: { name: 'Alex', height: '175', age: '28', sex: 'male' },
      revocationRegistryId: 'mock:uri',
      revocationStatusList,
      revocationConfiguration: new CredentialRevocationConfig({
        registryDefinition: revocationRegistryDefinition,
        registryDefinitionPrivate: revocationRegistryDefinitionPrivate,
        registryIndex: 9,
        tailsPath,
      }),
    })

    const credentialReceived = credential.process({
      credentialDefinition,
      credentialRequestMetadata,
      masterSecret,
      revocationRegistryDefinition,
    })

    const revocationRegistryIndex = credentialReceived.revocationRegistryIndex ?? 0

    const revocationState = CredentialRevocationState.create({
      revocationRegistryDefinition,
      revocationStatusList,
      revocationRegistryIndex,
      tailsPath,
    })

    const presentation = Presentation.create({
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
      schemas: { 'mock:uri': schema },
      selfAttest: { attr3_referent: '8-800-300' },
    })

    expect(presentation.handle.handle).toStrictEqual(expect.any(Number))

    const verify = Presentation.load(presentation.toJson()).verify({
      presentationRequest,
      schemas: { ['mock:uri']: schema },
      credentialDefinitions: { ['mock:uri']: credentialDefinition },
      revocationRegistryDefinitions: { ['mock:uri']: revocationRegistryDefinition },
      revocationStatusLists: [revocationStatusList],
    })

    expect(verify).toBeTruthy()
  })

  test('create and verify presentation (no revocation use case)', () => {
    const schema = Schema.create({
      name: 'schema-1',
      issuerId: 'mock:uri',
      version: '1',
      attributeNames: ['name', 'age', 'sex', 'height'],
    })

    const { credentialDefinition, keyCorrectnessProof, credentialDefinitionPrivate } = CredentialDefinition.create({
      schemaId: 'mock:uri',
      issuerId: 'mock:uri',
      schema,
      signatureType: 'CL',
      supportRevocation: false,
      tag: 'TAG',
    })

    const credentialOffer = CredentialOffer.create({
      schemaId: 'mock:uri',
      credentialDefinitionId: 'mock:uri',
      keyCorrectnessProof,
    })

    const masterSecret = MasterSecret.create()
    const masterSecretId = 'master secret id'

    const { credentialRequestMetadata, credentialRequest } = CredentialRequest.create({
      credentialDefinition,
      masterSecret,
      masterSecretId,
      credentialOffer,
    })

    const credential = Credential.create({
      credentialDefinition,
      credentialDefinitionPrivate,
      credentialOffer,
      credentialRequest,
      attributeRawValues: { name: 'Alex', height: '175', age: '28', sex: 'male' },
    })

    const credReceived = credential.process({
      credentialDefinition,
      credentialRequestMetadata,
      masterSecret,
    })

    const credJson = credential.toJson()
    expect(JSON.parse(credJson)).toEqual(
      expect.objectContaining({
        cred_def_id: 'mock:uri',
        schema_id: 'mock:uri',
      })
    )

    const credReceivedJson = credential.toJson()
    expect(JSON.parse(credReceivedJson)).toEqual(
      expect.objectContaining({
        cred_def_id: 'mock:uri',
        schema_id: 'mock:uri',
      })
    )
    expect(JSON.parse(credReceivedJson)).toHaveProperty('signature')
    expect(JSON.parse(credReceivedJson)).toHaveProperty('witness')

    const nonce = anoncreds.generateNonce()

    const presentationRequest = PresentationRequest.load(
      JSON.stringify({
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
      })
    )

    const presentation = Presentation.create({
      presentationRequest,
      credentials: [
        {
          credential: credReceived,
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
      schemas: { 'mock:uri': schema },
      selfAttest: { attr3_referent: '8-800-300' },
    })

    expect(presentation.handle.handle).toStrictEqual(expect.any(Number))

    const verify = Presentation.load(presentation.toJson()).verify({
      presentationRequest,
      schemas: { ['mock:uri']: schema },
      credentialDefinitions: { ['mock:uri']: credentialDefinition },
    })

    expect(verify).toBeTruthy()
  })
})
