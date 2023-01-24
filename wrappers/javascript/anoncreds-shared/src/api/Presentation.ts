import type { ObjectHandle } from '../ObjectHandle'
import type { Credential } from './Credential'
import type { CredentialDefinition } from './CredentialDefinition'
import type { CredentialRevocationState } from './CredentialRevocationState'
import type { MasterSecret } from './MasterSecret'
import type { PresentationRequest } from './PresentationRequest'
import type { RevocationRegistry } from './RevocationRegistry'
import type { RevocationRegistryDefinition } from './RevocationRegistryDefinition'
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
  presentation: Presentation
  presentationRequest: PresentationRequest
  schemas: Schema[]
  credentialDefinitions: CredentialDefinition[]
  revocationRegistryDefinitions: RevocationRegistryDefinition[]
  revocationEntries: RevocationEntry[]
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
    return anoncreds.verifyPresentation({
      presentation: options.presentation.handle,
      presentationRequest: options.presentationRequest.handle,
      schemas: options.schemas.map((object) => object.handle),
      credentialDefinitions: options.credentialDefinitions.map((object) => object.handle),
      revocationRegistryDefinitions: options.revocationRegistryDefinitions.map((object) => object.handle),
      revocationEntries: options.revocationEntries.map((item) => ({
        entry: item.entry.handle,
        revocationRegistryDefinitionEntryIndex: item.revocationRegistryDefinitionEntryIndex,
        timestamp: item.timestamp,
      })),
    })
  }
}
