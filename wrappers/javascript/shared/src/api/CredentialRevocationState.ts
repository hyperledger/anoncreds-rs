import type { RevocationRegistryDefinition } from './RevocationRegistryDefinition'
import type { RevocationRegistryDelta } from './RevocationRegistryDelta'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

export type CreateRevocationStateOptions = {
  revocationRegistryDefinition: RevocationRegistryDefinition
  revocationRegistryStatusList: RevocationRegistryDelta
  revocationRegistryIndex: number
  tailsPath: string
  previousRevocationState?: CredentialRevocationState
}

export type UpdateRevocationStateOptions = CreateRevocationStateOptions

export class CredentialRevocationState extends AnoncredsObject {
  public static create(options: CreateRevocationStateOptions) {
    return new CredentialRevocationState(
      anoncreds.createOrUpdateRevocationState({
        revocationRegistryDefinition: options.revocationRegistryDefinition.handle,
        revocationRegistryIndex: options.revocationRegistryIndex,
        tailsPath: options.tailsPath,
        revocationStatusList: options.revocationRegistryStatusList.handle,
        previousRevocationState: options.previousRevocationState?.handle,
      }).handle
    )
  }

  public static load(json: string) {
    return new CredentialRevocationState(anoncreds.revocationStateFromJson({ json }).handle)
  }

  public update(options: UpdateRevocationStateOptions) {
    this.handle = anoncreds.createOrUpdateRevocationState({
      revocationRegistryDefinition: options.revocationRegistryDefinition.handle,
      revocationRegistryIndex: options.revocationRegistryIndex,
      tailsPath: options.tailsPath,
      revocationStatusList: options.revocationRegistryStatusList.handle,
      previousRevocationState: options.previousRevocationState?.handle,
    })
  }
}
