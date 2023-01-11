import { IndyObject } from '../IndyObject'
import { indyCredx } from '../register'

export class KeyCorrectnessProof extends IndyObject {
  public static load(json: string) {
    return new KeyCorrectnessProof(indyCredx.keyCorrectnessProofFromJson({ json }).handle)
  }
}
