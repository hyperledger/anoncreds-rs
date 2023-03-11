import type { JsonObject } from './types'

import { ObjectHandle } from './ObjectHandle'
import { anoncreds } from './register'

export class AnoncredsObject {
  public handle: ObjectHandle

  public constructor(handle: number) {
    this.handle = new ObjectHandle(handle)
  }

  public toJson() {
    return JSON.parse(anoncreds.getJson({ objectHandle: this.handle })) as JsonObject
  }
}
