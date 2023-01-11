import { IndyObject } from '../IndyObject'
import { indyCredx } from '../register'

export class PresentationRequest extends IndyObject {
  public static load(json: string) {
    return new PresentationRequest(indyCredx.presentationRequestFromJson({ json }).handle)
  }
}
