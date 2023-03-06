import type { JsonObject } from '../types'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

export class RevocationRegistryDefinitionPrivate extends AnoncredsObject {
  public static fromJson(json: JsonObject) {
    return new RevocationRegistryDefinitionPrivate(
      anoncreds.revocationRegistryDefinitionPrivateFromJson({ json: JSON.stringify(json) }).handle
    )
  }
}
