import { ObjectHandle } from './ObjectHandle'
import { AnoncredsError } from './error'
import { anoncreds } from './register'

export class AnoncredsObject {
  protected _handle: ObjectHandle

  public constructor(handle: number) {
    this._handle = new ObjectHandle(handle)
  }

  public get handle(): ObjectHandle {
    return this._handle
  }

  // TODO: do we need this?
  public copy() {
    return new AnoncredsObject(this._handle.handle)
  }

  // TODO: do we need this?
  public toBytes() {
    throw new AnoncredsError({ code: 100, message: 'Method toBytes not implemented' })
  }

  public toJson() {
    return anoncreds.getJson({ objectHandle: this._handle })
  }

  // TODO: do we need this?
  public toJsonBuffer() {
    throw new AnoncredsError({ code: 100, message: 'Method toJsonBuffer not implemented' })
  }
}
