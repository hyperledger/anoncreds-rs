import type { ObjectHandle } from '../ObjectHandle'
import type { JsonObject } from '../types'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

import { RevocationRegistryDefinition } from './RevocationRegistryDefinition'
import { pushToArray } from './utils'

export type CreateRevocationStatusListOptions = {
  revocationRegistryDefinitionId: string
  revocationRegistryDefinition: RevocationRegistryDefinition | JsonObject
  issuerId: string
  timestamp?: number
  issuanceByDefault: boolean
}

export type UpdateRevocationStatusListTimestampOptions = {
  timestamp: number
}

export type UpdateRevocationStatusListOptions = {
  revocationRegistryDefinition: RevocationRegistryDefinition | JsonObject
  timestamp?: number
  issued?: Array<number>
  revoked?: Array<number>
}

export class RevocationStatusList extends AnoncredsObject {
  public static create(options: CreateRevocationStatusListOptions) {
    let revocationStatusListHandle
    const objectHandles: ObjectHandle[] = []
    try {
      const revocationRegistryDefinition =
        options.revocationRegistryDefinition instanceof RevocationRegistryDefinition
          ? options.revocationRegistryDefinition.handle
          : pushToArray(
              RevocationRegistryDefinition.fromJson(options.revocationRegistryDefinition).handle,
              objectHandles
            )

      revocationStatusListHandle = anoncreds.createRevocationStatusList({
        ...options,
        revocationRegistryDefinition,
      }).handle
    } finally {
      objectHandles.forEach((handle) => handle.clear())
    }
    return new RevocationStatusList(revocationStatusListHandle)
  }

  public static fromJson(json: JsonObject) {
    return new RevocationStatusList(anoncreds.revocationStatusListFromJson({ json: JSON.stringify(json) }).handle)
  }

  public updateTimestamp(options: UpdateRevocationStatusListTimestampOptions) {
    const updatedRevocationStatusList = anoncreds.updateRevocationStatusListTimestampOnly({
      timestamp: options.timestamp,
      currentRevocationStatusList: this.handle,
    })

    this.handle = updatedRevocationStatusList
  }

  public update(options: UpdateRevocationStatusListOptions) {
    const objectHandles: ObjectHandle[] = []
    try {
      const revocationRegistryDefinition =
        options.revocationRegistryDefinition instanceof RevocationRegistryDefinition
          ? options.revocationRegistryDefinition.handle
          : pushToArray(
              RevocationRegistryDefinition.fromJson(options.revocationRegistryDefinition).handle,
              objectHandles
            )

      const updatedRevocationStatusList = anoncreds.updateRevocationStatusList({
        ...options,
        revocationRegistryDefinition,
        currentRevocationStatusList: this.handle,
      })

      this.handle = updatedRevocationStatusList
    } finally {
      objectHandles.forEach((handle) => handle.clear())
    }
  }
}
