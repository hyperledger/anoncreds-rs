import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

export class KeyCorrectnessProof extends AnoncredsObject {
  public static load(json: string) {
    return new KeyCorrectnessProof(anoncreds.keyCorrectnessProofFromJson({ json }).handle)
  }
}
