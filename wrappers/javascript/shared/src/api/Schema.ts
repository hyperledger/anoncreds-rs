import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

export type CreateSchemaOptions = {
  originDid: string
  name: string
  version: string
  attributeNames: string[]
  sequenceNumber?: number
}

export class Schema extends AnoncredsObject {
  public static create(options: CreateSchemaOptions) {
    return new Schema(anoncreds.createSchema(options).handle)
  }

  public static load(json: string) {
    return new Schema(anoncreds.schemaFromJson({ json }).handle)
  }

  public getId() {
    return anoncreds.schemaGetAttribute({ objectHandle: this.handle, name: 'id' })
  }
}
