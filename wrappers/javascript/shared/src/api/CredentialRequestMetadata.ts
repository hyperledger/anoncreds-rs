import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

export class CredentialRequestMetadata extends AnoncredsObject {
  public static load(json: string) {
    return new CredentialRequestMetadata(anoncreds.credentialRequestMetadataFromJson({ json }).handle)
  }
}
