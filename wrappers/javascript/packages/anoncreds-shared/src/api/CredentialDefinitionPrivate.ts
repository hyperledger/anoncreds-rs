import type { JsonObject } from '../types'

import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

export class CredentialDefinitionPrivate extends AnoncredsObject {
  public static fromJson(json: JsonObject) {
    return new CredentialDefinitionPrivate(
      anoncreds.credentialDefinitionPrivateFromJson({ json: JSON.stringify(json) }).handle
    )
  }
}
