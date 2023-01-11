import { ObjectHandle } from './ObjectHandle'
import { IndyCredxError } from './error'
import { indyCredx } from './register'

export class IndyObject {
  protected _handle: ObjectHandle

  public constructor(handle: number) {
    this._handle = new ObjectHandle(handle)
  }

  public get handle(): ObjectHandle {
    return this._handle
  }

  // TODO: do we need this?
  public copy() {
    return new IndyObject(this._handle.handle)
  }

  // TODO: do we need this?
  public toBytes() {
    throw new IndyCredxError({ code: 100, message: 'Method toBytes not implemented' })
  }

  public toJson() {
    return indyCredx.getJson({ objectHandle: this._handle })
  }

  // TODO: do we need this?
  public toJsonBuffer() {
    throw new IndyCredxError({ code: 100, message: 'Method toJsonBuffer not implemented' })
  }
}
