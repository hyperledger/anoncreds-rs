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

  public static customError({ message }: { message: string }) {
    return new AnoncredsError({ message, code: 100 })
  }
}

export function handleInvalidNullResponse<T>(response: T): Exclude<T, null> {
  if (response === null) {
    throw AnoncredsError.customError({ message: 'Invalid response. Expected value but received null pointer' })
  }

  return response as Exclude<T, null>
}
