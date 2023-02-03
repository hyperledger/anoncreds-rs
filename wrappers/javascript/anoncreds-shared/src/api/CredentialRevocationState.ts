import type { RevocationRegistryDefinition } from './RevocationRegistryDefinition'
import type { RevocationRegistryDelta } from './RevocationRegistryDelta'
import type { RevocationStatusList } from './RevocationStatusList'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

export type CreateRevocationStateOptions = {
  revocationRegistryDefinition: RevocationRegistryDefinition
  revocationStatusList: RevocationStatusList
  revocationRegistryIndex: number
  tailsPath: string
  oldRevocationStatusList?: RevocationRegistryDelta
  previousRevocationState?: CredentialRevocationState
}

export type UpdateRevocationStateOptions = Required<
  Pick<CreateRevocationStateOptions, 'oldRevocationStatusList' | 'previousRevocationState'>
> &
  Omit<CreateRevocationStateOptions, 'oldRevocationStatusList' | 'previousRevocationState'>

export class CredentialRevocationState extends AnoncredsObject {
  public static create(options: CreateRevocationStateOptions) {
    return new CredentialRevocationState(
      anoncreds.createOrUpdateRevocationState({
        revocationRegistryDefinition: options.revocationRegistryDefinition.handle,
        revocationStatusList: options.revocationStatusList.handle,
        revocationRegistryIndex: options.revocationRegistryIndex,
        tailsPath: options.tailsPath,
        oldRevocationStatusList: undefined,
        previousRevocationState: undefined,
      }).handle
    )
  }

  public static load(json: string) {
    return new CredentialRevocationState(anoncreds.revocationStateFromJson({ json }).handle)
  }

  public update(options: UpdateRevocationStateOptions) {
    this.handle = anoncreds.createOrUpdateRevocationState({
      revocationRegistryDefinition: options.revocationRegistryDefinition.handle,
      revocationStatusList: options.revocationStatusList.handle,
      revocationRegistryIndex: options.revocationRegistryIndex,
      tailsPath: options.tailsPath,
      oldRevocationStatusList: options.oldRevocationStatusList.handle,
      previousRevocationState: options.previousRevocationState.handle,
    })
  }
}
