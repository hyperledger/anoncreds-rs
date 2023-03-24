import type { ObjectHandle } from '../ObjectHandle'
import type { JsonObject } from '../types'
import type { RevocationRegistry } from './RevocationRegistry'
import type { RevocationStatusList } from './RevocationStatusList'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

import { Credential } from './Credential'
import { CredentialDefinition } from './CredentialDefinition'
import { CredentialRevocationState } from './CredentialRevocationState'
import { PresentationRequest } from './PresentationRequest'
import { RevocationRegistryDefinition } from './RevocationRegistryDefinition'
import { Schema } from './Schema'
import { pushToArray } from './utils'

// TODO: Simplify Presentation API (see PresentCredentials object in python wrapper))

// TODO: define whether what is undefined and what is defined
export type NonRevokedIntervalOverride = {
  revocationRegistryDefinitionId: string
  requestedFromTimestamp: number
  overrideRevocationStatusListTimestamp: number
}

export type CredentialEntry = {
  credential: Credential | JsonObject
  timestamp?: number
  revocationState?: CredentialRevocationState | JsonObject
}

export type CredentialProve = {
  entryIndex: number
  referent: string
  isPredicate: boolean
  reveal: boolean
}

export type RevocationEntry = {
  revocationRegistryDefinitionEntryIndex: number
  entry: RevocationRegistry
  timestamp: number
}

export type CreatePresentationOptions = {
  presentationRequest: PresentationRequest | JsonObject
  credentials: CredentialEntry[]
  credentialsProve: CredentialProve[]
  selfAttest: Record<string, string>
  linkSecret: string
  schemas: Record<string, Schema | JsonObject>
  credentialDefinitions: Record<string, CredentialDefinition | JsonObject>
}

export type VerifyPresentationOptions = {
  presentationRequest: PresentationRequest | JsonObject
  schemas: Record<string, Schema | JsonObject>
  credentialDefinitions: Record<string, CredentialDefinition | JsonObject>
  revocationRegistryDefinitions?: Record<string, RevocationRegistryDefinition | JsonObject>
  revocationStatusLists?: RevocationStatusList[]
  nonRevokedIntervalOverride?: NonRevokedIntervalOverride[]
}

export class Presentation extends AnoncredsObject {
  public static create(options: CreatePresentationOptions) {
    let presentationHandle
    // Objects created within this method must be freed up
    const objectHandles: ObjectHandle[] = []
    try {
      const presentationRequest =
        options.presentationRequest instanceof PresentationRequest
          ? options.presentationRequest.handle
          : pushToArray(PresentationRequest.fromJson(options.presentationRequest).handle, objectHandles)

      presentationHandle = anoncreds.createPresentation({
        presentationRequest,
        credentials: options.credentials.map((item) => ({
          credential:
            item.credential instanceof Credential
              ? item.credential.handle
              : pushToArray(Credential.fromJson(item.credential).handle, objectHandles),
          revocationState:
            item.revocationState instanceof CredentialRevocationState
              ? item.revocationState.handle
              : item.revocationState !== undefined
              ? pushToArray(CredentialRevocationState.fromJson(item.revocationState).handle, objectHandles)
              : undefined,

          timestamp: item.timestamp,
        })),
        credentialsProve: options.credentialsProve,
        selfAttest: options.selfAttest,
        linkSecret: options.linkSecret,
        schemas: Object.entries(options.schemas).reduce<Record<string, ObjectHandle>>((prev, [id, object]) => {
          const objectHandle =
            object instanceof Schema ? object.handle : pushToArray(Schema.fromJson(object).handle, objectHandles)

          prev[id] = objectHandle
          return prev
        }, {}),
        credentialDefinitions: Object.entries(options.credentialDefinitions).reduce<Record<string, ObjectHandle>>(
          (prev, [id, object]) => {
            const objectHandle =
              object instanceof CredentialDefinition
                ? object.handle
                : pushToArray(CredentialDefinition.fromJson(object).handle, objectHandles)

            prev[id] = objectHandle
            return prev
          },
          {}
        ),
      }).handle
    } finally {
      objectHandles.forEach((handle) => handle.clear())
    }
    return new Presentation(presentationHandle)
  }

  public static fromJson(json: JsonObject) {
    return new Presentation(anoncreds.presentationFromJson({ json: JSON.stringify(json) }).handle)
  }

  public verify(options: VerifyPresentationOptions) {
    const schemas = Object.values(options.schemas)
    const schemaIds = Object.keys(options.schemas)

    const credentialDefinitions = Object.values(options.credentialDefinitions)
    const credentialDefinitionIds = Object.keys(options.credentialDefinitions)

    const revocationRegistryDefinitions = options.revocationRegistryDefinitions
      ? Object.values(options.revocationRegistryDefinitions)
      : undefined

    const revocationRegistryDefinitionIds = options.revocationRegistryDefinitions
      ? Object.keys(options.revocationRegistryDefinitions)
      : undefined

    let verified
    const objectHandles: ObjectHandle[] = []
    try {
      const presentationRequest =
        options.presentationRequest instanceof PresentationRequest
          ? options.presentationRequest.handle
          : pushToArray(PresentationRequest.fromJson(options.presentationRequest).handle, objectHandles)

      verified = anoncreds.verifyPresentation({
        presentation: this.handle,
        presentationRequest,
        schemas: schemas.map((o) =>
          o instanceof Schema ? o.handle : pushToArray(Schema.fromJson(o).handle, objectHandles)
        ),
        schemaIds,
        credentialDefinitions: credentialDefinitions.map((o) =>
          o instanceof CredentialDefinition
            ? o.handle
            : pushToArray(CredentialDefinition.fromJson(o).handle, objectHandles)
        ),
        credentialDefinitionIds,
        revocationRegistryDefinitions: revocationRegistryDefinitions?.map((o) =>
          o instanceof RevocationRegistryDefinition
            ? o.handle
            : pushToArray(RevocationRegistryDefinition.fromJson(o).handle, objectHandles)
        ),
        revocationRegistryDefinitionIds,
        revocationStatusLists: options.revocationStatusLists?.map((o) => o.handle),
        nonRevokedIntervalOverride: options.nonRevokedIntervalOverride,
      })
    } finally {
      objectHandles.forEach((handle) => handle.clear())
    }
    return verified
  }
}
