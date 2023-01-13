export type AnoncredsErrorObject = {
  code: number
  extra?: string
  message: string
}

export class AnoncredsError extends Error {
  public readonly code: number
  public readonly extra?: string

  public constructor({ code, message, extra }: AnoncredsErrorObject) {
    super(message)
    this.code = code
    this.extra = extra
  }
}
