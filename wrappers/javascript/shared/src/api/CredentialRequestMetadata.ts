import { IndyObject } from '../IndyObject'
import { indyCredx } from '../register'

export class CredentialRequestMetadata extends IndyObject {
  public static load(json: string) {
    return new CredentialRequestMetadata(indyCredx.credentialRequestMetadataFromJson({ json }).handle)
  }
}
