export type IndyCredxErrorObject = {
  code: number
  extra?: string
  message: string
}

export class IndyCredxError extends Error {
  public readonly code: number
  public readonly extra?: string

  public constructor({ code, message, extra }: IndyCredxErrorObject) {
    super(message)
    this.code = code
    this.extra = extra
  }
}
