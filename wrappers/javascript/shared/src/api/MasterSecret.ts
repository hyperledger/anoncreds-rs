import { IndyObject } from '../IndyObject'
import { indyCredx } from '../register'

export class MasterSecret extends IndyObject {
  public static create() {
    return new MasterSecret(indyCredx.createMasterSecret().handle)
  }

  public static load(json: string) {
    return new MasterSecret(indyCredx.masterSecretFromJson({ json }).handle)
  }
}
