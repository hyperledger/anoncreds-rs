import type { Credential } from './Credential'
import type { CredentialDefinition } from './CredentialDefinition'
import type { CredentialRevocationState } from './CredentialRevocationState'
import type { MasterSecret } from './MasterSecret'
import type { PresentationRequest } from './PresentationRequest'
import type { RevocationRegistry } from './RevocationRegistry'
import type { RevocationRegistryDefinition } from './RevocationRegistryDefinition'
import type { Schema } from './Schema'

import { IndyObject } from '../IndyObject'
import { indyCredx } from '../register'

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
  schemas: Schema[]
  credentialDefinitions: CredentialDefinition[]
}

export type VerifyPresentationOptions = {
  presentation: Presentation
  presentationRequest: PresentationRequest
  schemas: Schema[]
  credentialDefinitions: CredentialDefinition[]
  revocationRegistryDefinitions: RevocationRegistryDefinition[]
  revocationEntries: RevocationEntry[]
}

export class Presentation extends IndyObject {
  public static create(options: CreatePresentationOptions) {
    return new Presentation(
      indyCredx.createPresentation({
        presentationRequest: options.presentationRequest.handle,
        credentials: options.credentials.map((item) => ({
          credential: item.credential.handle,
          revocationState: item.revocationState.handle,
          timestamp: item.timestamp,
        })),
        credentialsProve: options.credentialsProve,
        selfAttest: options.selfAttest,
        masterSecret: options.masterSecret.handle,
        schemas: options.schemas.map((object) => object.handle),
        credentialDefinitions: options.credentialDefinitions.map((object) => object.handle),
      }).handle
    )
  }

  public static load(json: string) {
    return new Presentation(indyCredx.presentationFromJson({ json }).handle)
  }

  public verify(options: VerifyPresentationOptions) {
    return indyCredx.verifyPresentation({
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
