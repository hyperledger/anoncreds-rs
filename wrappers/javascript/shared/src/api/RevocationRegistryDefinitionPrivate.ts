import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

export class RevocationRegistryDefinitionPrivate extends AnoncredsObject {
  public static load(json: string) {
    return new RevocationRegistryDefinitionPrivate(
      anoncreds.revocationRegistryDefinitionPrivateFromJson({ json }).handle
    )
  }
}
