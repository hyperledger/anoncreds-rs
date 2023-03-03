import type { ObjectHandle } from '../ObjectHandle'
import type { JsonObject } from '../types'
import type { RevocationRegistryDelta } from './RevocationRegistryDelta'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

import { RevocationRegistryDefinition } from './RevocationRegistryDefinition'
import { RevocationStatusList } from './RevocationStatusList'
import { pushToArray } from './utils'

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
    const objectHandles: ObjectHandle[] = []
    try {
      const revocationRegistryDefinition =
        options.revocationRegistryDefinition instanceof RevocationRegistryDefinition
          ? options.revocationRegistryDefinition.handle
          : pushToArray(
              RevocationRegistryDefinition.fromJson(options.revocationRegistryDefinition).handle,
              objectHandles
            )

      const revocationStatusList =
        options.revocationStatusList instanceof RevocationStatusList
          ? options.revocationStatusList.handle
          : pushToArray(RevocationStatusList.fromJson(options.revocationStatusList).handle, objectHandles)

      return new CredentialRevocationState(
        anoncreds.createOrUpdateRevocationState({
          revocationRegistryDefinition,
          revocationStatusList,
          revocationRegistryIndex: options.revocationRegistryIndex,
          tailsPath: options.tailsPath,
          oldRevocationStatusList: undefined,
          previousRevocationState: undefined,
        }).handle
      )
    } finally {
      objectHandles.forEach((handle) => handle.clear())
    }
  }

  public static fromJson(json: JsonObject) {
    return new CredentialRevocationState(anoncreds.revocationStateFromJson({ json: JSON.stringify(json) }).handle)
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
