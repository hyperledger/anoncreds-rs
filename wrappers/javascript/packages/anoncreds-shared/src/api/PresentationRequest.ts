import type { JsonObject } from '../types'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

export class PresentationRequest extends AnoncredsObject {
  public static fromJson(json: JsonObject) {
    return new PresentationRequest(anoncreds.presentationRequestFromJson({ json: JSON.stringify(json) }).handle)
  }
}
