import { AnoncredsObject } from '../AnoncredsObject'
import { anoncreds } from '../register'

export type CreateSchemaOptions = {
  name: string
  version: string
  issuerId: string
  attributeNames: string[]
}

export class Schema extends AnoncredsObject {
  public static create(options: CreateSchemaOptions) {
    return new Schema(anoncreds.createSchema(options).handle)
  }

  public static load(json: string) {
    return new Schema(anoncreds.schemaFromJson({ json }).handle)
  }
}
