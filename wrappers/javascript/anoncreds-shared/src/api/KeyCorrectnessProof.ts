import type { JsonObject } from '../types'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

export class KeyCorrectnessProof extends AnoncredsObject {
  public static fromJson(json: JsonObject) {
    return new KeyCorrectnessProof(anoncreds.keyCorrectnessProofFromJson({ json: JSON.stringify(json) }).handle)
  }
}
