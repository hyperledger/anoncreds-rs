import type { JsonObject } from '../types'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

export class RevocationRegistryDelta extends AnoncredsObject {
  public static fromJson(json: JsonObject) {
    return new RevocationRegistryDelta(anoncreds.revocationRegistryDeltaFromJson({ json: JSON.stringify(json) }).handle)
  }
}
