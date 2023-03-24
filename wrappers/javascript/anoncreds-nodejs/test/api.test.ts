import {
  anoncreds,
  Credential,
  CredentialDefinition,
  CredentialOffer,
  CredentialRequest,
  CredentialRevocationConfig,
  CredentialRevocationState,
  LinkSecret,
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

    const presentationRequest = PresentationRequest.fromJson({
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
      issuerId: 'mock:uri',
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

    const linkSecret = LinkSecret.create()
    const linkSecretId = 'link secret id'

    const { credentialRequestMetadata, credentialRequest } = CredentialRequest.create({
      entropy: 'entropy',
      credentialDefinition,
      linkSecret,
      linkSecretId,
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
      linkSecret,
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
      linkSecret,
      schemas: { 'mock:uri': schema },
      selfAttest: { attr3_referent: '8-800-300' },
    })

    expect(presentation.handle.handle).toStrictEqual(expect.any(Number))

    const verify = presentation.verify({
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

    const linkSecret = LinkSecret.create()
    const linkSecretId = 'link secret id'

    const { credentialRequestMetadata, credentialRequest } = CredentialRequest.create({
      entropy: 'entropy',
      credentialDefinition,
      linkSecret,
      linkSecretId,
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
      linkSecret,
    })

    const credJson = credential.toJson()
    expect(credJson).toEqual(
      expect.objectContaining({
        cred_def_id: 'mock:uri',
        schema_id: 'mock:uri',
      })
    )

    const credReceivedJson = credential.toJson()
    expect(credReceivedJson).toEqual(
      expect.objectContaining({
        cred_def_id: 'mock:uri',
        schema_id: 'mock:uri',
      })
    )
    expect(credReceivedJson).toHaveProperty('signature')
    expect(credReceivedJson).toHaveProperty('witness')

    const nonce = anoncreds.generateNonce()

    const presentationRequest = PresentationRequest.fromJson({
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
      linkSecret,
      schemas: { 'mock:uri': schema },
      selfAttest: { attr3_referent: '8-800-300' },
    })

    expect(presentation.handle.handle).toStrictEqual(expect.any(Number))

    const verify = presentation.verify({
      presentationRequest,
      schemas: { ['mock:uri']: schema },
      credentialDefinitions: { ['mock:uri']: credentialDefinition },
    })

    expect(verify).toBeTruthy()
  })
})

test('create and verify presentation passing only JSON objects as parameters', () => {
  setup()

  const nonce = anoncreds.generateNonce()

  // a schema can be created from JSON
  const schema = Schema.fromJson({
    name: 'schema-1',
    issuerId: 'mock:uri',
    version: '1',
    attrNames: ['name', 'age', 'sex', 'height'],
  })
  expect(schema.toJson()).toEqual({
    name: 'schema-1',
    issuerId: 'mock:uri',
    version: '1',
    attrNames: expect.arrayContaining(['name', 'age', 'sex', 'height']),
  })

  const { credentialDefinition, keyCorrectnessProof, credentialDefinitionPrivate } = CredentialDefinition.create({
    schemaId: 'mock:uri',
    issuerId: 'mock:uri',
    schema: {
      name: 'schema-1',
      issuerId: 'mock:uri',
      version: '1',
      attrNames: ['name', 'age', 'sex', 'height'],
    },
    signatureType: 'CL',
    supportRevocation: false,
    tag: 'TAG',
  })

  const credentialOffer = CredentialOffer.fromJson({
    schema_id: 'mock:uri',
    cred_def_id: 'mock:uri',
    key_correctness_proof: keyCorrectnessProof.toJson(),
    nonce,
  })

  const linkSecret = '123'
  const linkSecretId = 'link secret id'

  const { credentialRequestMetadata, credentialRequest } = CredentialRequest.create({
    entropy: 'entropy',
    credentialDefinition: credentialDefinition.toJson(),
    linkSecret,
    linkSecretId,
    credentialOffer: credentialOffer.toJson(),
  })

  const credential = Credential.create({
    credentialDefinition: credentialDefinition.toJson(),
    credentialDefinitionPrivate: credentialDefinitionPrivate.toJson(),
    credentialOffer: credentialOffer.toJson(),
    credentialRequest: credentialRequest.toJson(),
    attributeRawValues: { name: 'Alex', height: '175', age: '28', sex: 'male' },
  })

  const credReceived = credential.process({
    credentialDefinition: credentialDefinition.toJson(),
    credentialRequestMetadata: credentialRequestMetadata.toJson(),
    linkSecret,
  })

  const credJson = credential.toJson()
  expect(credJson).toEqual(
    expect.objectContaining({
      cred_def_id: 'mock:uri',
      schema_id: 'mock:uri',
    })
  )

  const credReceivedJson = credential.toJson()
  expect(credReceivedJson).toEqual(
    expect.objectContaining({
      cred_def_id: 'mock:uri',
      schema_id: 'mock:uri',
    })
  )
  expect(credReceivedJson).toHaveProperty('signature')
  expect(credReceivedJson).toHaveProperty('witness')

  const presentationRequest = {
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
  }

  const presentation = Presentation.create({
    presentationRequest,
    credentials: [
      {
        credential: credReceived.toJson(),
      },
    ],
    credentialDefinitions: { 'mock:uri': credentialDefinition.toJson() },
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
    linkSecret,
    schemas: { 'mock:uri': schema.toJson() },
    selfAttest: { attr3_referent: '8-800-300' },
  })

  expect(presentation.handle.handle).toStrictEqual(expect.any(Number))

  const verify = Presentation.fromJson(presentation.toJson()).verify({
    presentationRequest,
    schemas: { ['mock:uri']: schema.toJson() },
    credentialDefinitions: { ['mock:uri']: credentialDefinition.toJson() },
  })

  expect(verify).toBeTruthy()
})
