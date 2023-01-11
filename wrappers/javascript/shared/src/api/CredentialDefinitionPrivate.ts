import { IndyObject } from '../IndyObject'
import { indyCredx } from '../register'

export class CredentialDefinitionPrivate extends IndyObject {
  public static load(json: string) {
    return new CredentialDefinitionPrivate(indyCredx.credentialDefinitionPrivateFromJson({ json }).handle)
  }
}
