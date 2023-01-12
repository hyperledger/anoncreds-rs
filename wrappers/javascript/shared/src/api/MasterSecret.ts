import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

export class MasterSecret extends AnoncredsObject {
  public static create() {
    return new MasterSecret(anoncreds.createMasterSecret().handle)
  }

  public static load(json: string) {
    return new MasterSecret(anoncreds.masterSecretFromJson({ json }).handle)
  }
}
