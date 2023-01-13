import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

export class PresentationRequest extends AnoncredsObject {
  public static load(json: string) {
    return new PresentationRequest(anoncreds.presentationRequestFromJson({ json }).handle)
  }
}
