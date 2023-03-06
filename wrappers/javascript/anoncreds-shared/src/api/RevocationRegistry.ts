import type { JsonObject } from '../types'
import type { RevocationRegistryDefinition } from './RevocationRegistryDefinition'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

export type RevokeCredentialOptions = {
  revocationRegistryDefinition: RevocationRegistryDefinition
  credentialRevocationIndex: number
  tailsPath: string
}

export type UpdateRevocationRegistryOptions = {
  revocationRegistryDefinition: RevocationRegistryDefinition
  issued: number[]
  revoked: number[]
  tailsDirectoryPath: string
}

export class RevocationRegistry extends AnoncredsObject {
  public static fromJson(json: JsonObject) {
    return new RevocationRegistry(anoncreds.revocationRegistryFromJson({ json: JSON.stringify(json) }).handle)
  }
}
