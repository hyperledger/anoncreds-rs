import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

export class RevocationRegistryDelta extends AnoncredsObject {
  public static load(json: string) {
    return new RevocationRegistryDelta(anoncreds.revocationRegistryDeltaFromJson({ json }).handle)
  }

  public updateWith(nextDelta: RevocationRegistryDelta) {
    this._handle = anoncreds.mergeRevocationRegistryDeltas({
      revocationRegistryDelta1: this.handle,
      revocationRegistryDelta2: nextDelta.handle,
    })
  }
}
