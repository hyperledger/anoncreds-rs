import { anoncreds } from './register'

export class ObjectHandle {
  private _handle: number

  public constructor(handle: number) {
    this._handle = handle
  }

  public get handle() {
    return this._handle
  }

  public typeName() {
    return anoncreds.getTypeName({ objectHandle: this })
  }

  // TODO: do we need this?
  public clear() {
    anoncreds.objectFree({ objectHandle: this })
  }
}
