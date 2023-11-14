import type { CredentialProve, NonRevokedIntervalOverride } from './Presentation'
import type { ObjectHandle } from '../ObjectHandle'
import type { JsonObject } from '../types'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

import { CredentialDefinition } from './CredentialDefinition'
import { CredentialRevocationState } from './CredentialRevocationState'
import { PresentationRequest } from './PresentationRequest'
import { RevocationRegistryDefinition } from './RevocationRegistryDefinition'
import { RevocationStatusList } from './RevocationStatusList'
import { Schema } from './Schema'
import { W3CCredential } from './W3CCredential'
import { pushToArray } from './utils'

// TODO: Simplify Presentation API (see PresentCredentials object in python wrapper))

export type W3CCredentialEntry = {
  credential: W3CCredential | JsonObject
  timestamp?: number
  revocationState?: CredentialRevocationState | JsonObject
}

export type CreateW3CPresentationOptions = {
  presentationRequest: PresentationRequest | JsonObject
  credentials: W3CCredentialEntry[]
  credentialsProve: CredentialProve[]
  linkSecret: string
  schemas: Record<string, Schema | JsonObject>
  credentialDefinitions: Record<string, CredentialDefinition | JsonObject>
}

export type VerifyW3CPresentationOptions = {
  presentationRequest: PresentationRequest | JsonObject
  schemas: Record<string, Schema | JsonObject>
  credentialDefinitions: Record<string, CredentialDefinition | JsonObject>
  revocationRegistryDefinitions?: Record<string, RevocationRegistryDefinition | JsonObject>
  revocationStatusLists?: (RevocationStatusList | JsonObject)[]
  nonRevokedIntervalOverrides?: NonRevokedIntervalOverride[]
}

export class W3CPresentation extends AnoncredsObject {
  public static create(options: CreateW3CPresentationOptions) {
    let presentationHandle
    // Objects created within this method must be freed up
    const objectHandles: ObjectHandle[] = []
    try {
      const presentationRequest =
        options.presentationRequest instanceof PresentationRequest
          ? options.presentationRequest.handle
          : pushToArray(PresentationRequest.fromJson(options.presentationRequest).handle, objectHandles)

      presentationHandle = anoncreds.createW3CPresentation({
        presentationRequest,
        credentials: options.credentials.map((item) => ({
          credential:
            item.credential instanceof W3CCredential
              ? item.credential.handle
              : pushToArray(W3CCredential.fromJson(item.credential).handle, objectHandles),
          revocationState:
            item.revocationState instanceof CredentialRevocationState
              ? item.revocationState.handle
              : item.revocationState !== undefined
              ? pushToArray(CredentialRevocationState.fromJson(item.revocationState).handle, objectHandles)
              : undefined,

          timestamp: item.timestamp
        })),
        credentialsProve: options.credentialsProve,
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
        )
      }).handle
    } finally {
      objectHandles.forEach((handle) => {
        handle.clear()
      })
    }
    return new W3CPresentation(presentationHandle)
  }

  public static fromJson(json: JsonObject) {
    return new W3CPresentation(anoncreds.w3cPresentationFromJson({ json: JSON.stringify(json) }).handle)
  }

  public verify(options: VerifyW3CPresentationOptions) {
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

      verified = anoncreds.verifyW3CPresentation({
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
        revocationStatusLists: options.revocationStatusLists?.map((o) =>
          o instanceof RevocationStatusList
            ? o.handle
            : pushToArray(RevocationStatusList.fromJson(o).handle, objectHandles)
        ),
        nonRevokedIntervalOverrides: options.nonRevokedIntervalOverrides
      })
    } finally {
      objectHandles.forEach((handle) => {
        handle.clear()
      })
    }
    return verified
  }
}
