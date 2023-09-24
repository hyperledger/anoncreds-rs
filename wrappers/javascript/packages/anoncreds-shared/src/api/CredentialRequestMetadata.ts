import type { JsonObject } from '../types'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

export class CredentialRequestMetadata extends AnoncredsObject {
  public static fromJson(json: JsonObject) {
    return new CredentialRequestMetadata(
      anoncreds.credentialRequestMetadataFromJson({ json: JSON.stringify(json) }).handle
    )
  }
}
