import type { RevocationRegistryDefinition } from './RevocationRegistryDefinition'
import type { RevocationRegistryDelta } from './RevocationRegistryDelta'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

export type CreateRevocationStateOptions = {
  revocationRegistryDefinition: RevocationRegistryDefinition
  revocationRegistryDelta: RevocationRegistryDelta
  revocationRegistryIndex: number
  timestamp: number
  tailsPath: string
}

export type UpdateRevocationStateOptions = {
  revocationRegistryDefinition: RevocationRegistryDefinition
  revocationRegistryDelta: RevocationRegistryDelta
  revocationRegistryIndex: number
  timestamp: number
  tailsPath: string
}

export class CredentialRevocationState extends AnoncredsObject {
  public static create(options: CreateRevocationStateOptions) {
    return new CredentialRevocationState(
      anoncreds.createOrUpdateRevocationState({
        revocationRegistryDefinition: options.revocationRegistryDefinition.handle,
        revocationRegistryDelta: options.revocationRegistryDelta.handle,
        revocationRegistryIndex: options.revocationRegistryIndex,
        timestamp: options.timestamp,
        tailsPath: options.tailsPath,
      }).handle
    )
  }

  public static load(json: string) {
    return new CredentialRevocationState(anoncreds.revocationStateFromJson({ json }).handle)
  }

  public update(options: UpdateRevocationStateOptions) {
    this._handle = anoncreds.createOrUpdateRevocationState({
      revocationRegistryDefinition: options.revocationRegistryDefinition.handle,
      revocationRegistryDelta: options.revocationRegistryDelta.handle,
      revocationRegistryIndex: options.revocationRegistryIndex,
      timestamp: options.timestamp,
      tailsPath: options.tailsPath,
      previousRevocationState: this.handle,
    })
  }
}
