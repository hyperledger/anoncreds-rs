import type { RevocationRegistryDefinition } from './RevocationRegistryDefinition'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

export type CreateRevocationStatusListOptions = {
  revocationRegistryDefinitionId: string
  revocationRegistryDefinition: RevocationRegistryDefinition
  timestamp?: number
  issuanceByDefault: boolean
}

export type UpdateRevocationStatusListTimestampOptions = {
  timestamp: number
}

export type UpdateRevocationStatusListOptions = {
  timestamp?: number
  issued?: Array<number>
  revoked?: Array<number>
  revocationRegstryDefinition: RevocationRegistryDefinition
}

export class RevocationStatusList extends AnoncredsObject {
  public static create(options: CreateRevocationStatusListOptions) {
    const revocationRegistryDefinitionObjectHandle = options.revocationRegistryDefinition.handle
    const revocationStatusList = anoncreds.createRevocationStatusList({
      ...options,
      revocationRegistryDefinition: revocationRegistryDefinitionObjectHandle,
    })

    return new RevocationStatusList(revocationStatusList.handle)
  }

  public updateTimestamp(options: UpdateRevocationStatusListTimestampOptions) {
    const updatedRevocationStatusList = anoncreds.updateRevocationStatusListTimestampOnly({
      timestamp: options.timestamp,
      currentRevocationStatusList: this.handle,
    })

    this.handle = updatedRevocationStatusList
  }

  public update(options: UpdateRevocationStatusListOptions) {
    const updatedRevocationStatusList = anoncreds.updateRevocationStatusList({
      ...options,
      revocationRegistryDefinition: options.revocationRegstryDefinition.handle,
      currentRevocationStatusList: this.handle,
    })

    this.handle = updatedRevocationStatusList
  }
}
