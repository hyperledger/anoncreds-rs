import { IndyObject } from '../IndyObject'
import { indyCredx } from '../register'

export type CreateSchemaOptions = {
  originDid: string
  name: string
  version: string
  attributeNames: string[]
  sequenceNumber?: number
}

export class Schema extends IndyObject {
  public static create(options: CreateSchemaOptions) {
    return new Schema(indyCredx.createSchema(options).handle)
  }

  public static load(json: string) {
    return new Schema(indyCredx.schemaFromJson({ json }).handle)
  }

  public getId() {
    return indyCredx.schemaGetAttribute({ objectHandle: this.handle, name: 'id' })
  }
}
