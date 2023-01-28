import type { ObjectHandle } from '../ObjectHandle'
import type { Credential } from './Credential'
import type { CredentialDefinition } from './CredentialDefinition'
import type { CredentialRevocationState } from './CredentialRevocationState'
import type { MasterSecret } from './MasterSecret'
import type { PresentationRequest } from './PresentationRequest'
import type { RevocationRegistry } from './RevocationRegistry'
import type { RevocationRegistryDefinition } from './RevocationRegistryDefinition'
import type { RevocationStatusList } from './RevocationStatusList'
import type { Schema } from './Schema'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

// TODO: Simplify Presentation API (see PresentCredentials object in python wrapper))

export type CredentialEntry = {
  credential: Credential
  timestamp: number
  revocationState: CredentialRevocationState
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
  presentationRequest: PresentationRequest
  credentials: CredentialEntry[]
  credentialsProve: CredentialProve[]
  selfAttest: Record<string, string>
  masterSecret: MasterSecret
  schemas: Record<string, Schema>
  credentialDefinitions: Record<string, CredentialDefinition>
}

export type VerifyPresentationOptions = {
  presentationRequest: PresentationRequest
  schemas: Record<string, Schema>
  credentialDefinitions: Record<string, CredentialDefinition>
  revocationRegistryDefinitions?: Record<string, RevocationRegistryDefinition>
  revocationStatusLists?: RevocationStatusList[]
}

export class Presentation extends AnoncredsObject {
  public static create(options: CreatePresentationOptions) {
    return new Presentation(
      anoncreds.createPresentation({
        presentationRequest: options.presentationRequest.handle,
        credentials: options.credentials.map((item) => ({
          credential: item.credential.handle,
          revocationState: item.revocationState.handle,
          timestamp: item.timestamp,
        })),
        credentialsProve: options.credentialsProve,
        selfAttest: options.selfAttest,
        masterSecret: options.masterSecret.handle,
        schemas: Object.entries(options.schemas).reduce<Record<string, ObjectHandle>>((prev, [id, object]) => {
          prev[id] = object.handle
          return prev
        }, {}),
        credentialDefinitions: Object.entries(options.credentialDefinitions).reduce<Record<string, ObjectHandle>>(
          (prev, [id, object]) => {
            prev[id] = object.handle
            return prev
          },
          {}
        ),
      }).handle
    )
  }

  public static load(json: string) {
    return new Presentation(anoncreds.presentationFromJson({ json }).handle)
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

    return anoncreds.verifyPresentation({
      presentation: this.handle,
      presentationRequest: options.presentationRequest.handle,
      schemas: schemas.map((object) => object.handle),
      schemaIds,
      credentialDefinitions: credentialDefinitions.map((o) => o.handle),
      credentialDefinitionIds,
      revocationRegistryDefinitions: revocationRegistryDefinitions?.map((o) => o.handle),
      revocationRegistryDefinitionIds,
      revocationStatusLists: options.revocationStatusLists?.map((o) => o.handle),
    })
  }
}
