import type { RevocationRegistryDefinition } from './RevocationRegistryDefinition'
import type { RevocationRegistryDelta } from './RevocationRegistryDelta'

import { IndyObject } from '../IndyObject'
import { indyCredx } from '../register'

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

export class CredentialRevocationState extends IndyObject {
  public static create(options: CreateRevocationStateOptions) {
    return new CredentialRevocationState(
      indyCredx.createOrUpdateRevocationState({
        revocationRegistryDefinition: options.revocationRegistryDefinition.handle,
        revocationRegistryDelta: options.revocationRegistryDelta.handle,
        revocationRegistryIndex: options.revocationRegistryIndex,
        timestamp: options.timestamp,
        tailsPath: options.tailsPath,
      }).handle
    )
  }

  public static load(json: string) {
    return new CredentialRevocationState(indyCredx.revocationStateFromJson({ json }).handle)
  }

  public update(options: UpdateRevocationStateOptions) {
    this._handle = indyCredx.createOrUpdateRevocationState({
      revocationRegistryDefinition: options.revocationRegistryDefinition.handle,
      revocationRegistryDelta: options.revocationRegistryDelta.handle,
      revocationRegistryIndex: options.revocationRegistryIndex,
      timestamp: options.timestamp,
      tailsPath: options.tailsPath,
      previousRevocationState: this.handle,
    })
  }
}
