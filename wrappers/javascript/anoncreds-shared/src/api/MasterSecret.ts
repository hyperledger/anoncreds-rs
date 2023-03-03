import type { JsonObject } from '../types'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

export class MasterSecret extends AnoncredsObject {
  public static create() {
    return new MasterSecret(anoncreds.createMasterSecret().handle)
  }

  public static fromJson(json: JsonObject) {
    return new MasterSecret(anoncreds.masterSecretFromJson({ json: JSON.stringify(json) }).handle)
  }
}
