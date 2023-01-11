import { IndyObject } from '../IndyObject'
import { indyCredx } from '../register'

export class RevocationRegistryDefinitionPrivate extends IndyObject {
  public static load(json: string) {
    return new RevocationRegistryDefinitionPrivate(
      indyCredx.revocationRegistryDefinitionPrivateFromJson({ json }).handle
    )
  }
}
