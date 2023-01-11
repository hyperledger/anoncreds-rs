import { IndyObject } from '../IndyObject'
import { indyCredx } from '../register'

export class RevocationRegistryDelta extends IndyObject {
  public static load(json: string) {
    return new RevocationRegistryDelta(indyCredx.revocationRegistryDeltaFromJson({ json }).handle)
  }

  public updateWith(nextDelta: RevocationRegistryDelta) {
    this._handle = indyCredx.mergeRevocationRegistryDeltas({
      revocationRegistryDelta1: this.handle,
      revocationRegistryDelta2: nextDelta.handle,
    })
  }
}
