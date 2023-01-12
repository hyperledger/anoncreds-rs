import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

export class CredentialDefinitionPrivate extends AnoncredsObject {
  public static load(json: string) {
    return new CredentialDefinitionPrivate(anoncreds.credentialDefinitionPrivateFromJson({ json }).handle)
  }
}
