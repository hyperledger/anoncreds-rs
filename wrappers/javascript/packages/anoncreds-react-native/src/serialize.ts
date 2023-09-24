import { ObjectHandle } from '@hyperledger/anoncreds-shared'

export type ReturnObject<T = unknown> = {
  errorCode: number
  value?: null | T
}

type Argument = SerializedArgument | Date | boolean | ObjectHandle

type SerializedArgument = string | number | unknown[] | Record<string, unknown>

type SerializedArguments = Record<string, SerializedArgument>

export type SerializedOptions<Type> = {
  [Property in keyof Type]: Type[Property] extends string
    ? string
    : Type[Property] extends boolean
    ? number
    : Type[Property] extends Record<string, string>
    ? string
    : Type[Property] extends Record<string, string> | undefined
    ? string | undefined
    : Type[Property] extends ObjectHandle[]
    ? number[]
    : Type[Property] extends ObjectHandle[] | undefined
    ? number[]
    : Type[Property] extends string[]
    ? string[]
    : Type[Property] extends string[] | undefined
    ? string[]
    : Type[Property] extends Date
    ? number
    : Type[Property] extends Date | undefined
    ? number | undefined
    : Type[Property] extends ObjectHandle
    ? number
    : Type[Property] extends ObjectHandle | undefined
    ? number | undefined
    : Type[Property]
}

const serialize = (arg: Argument): SerializedArgument => {
  switch (typeof arg) {
    case 'undefined':
      return arg
    case 'string':
      return arg
    case 'boolean':
      return Number(arg)
    case 'number':
      return arg
    case 'function':
      return arg
    case 'object':
      if (arg instanceof Date) {
        return arg.valueOf()
      } else if (arg instanceof ObjectHandle) {
        return arg.handle
      } else if (Array.isArray(arg) && arg[0] instanceof ObjectHandle) {
        return (arg as ObjectHandle[]).map((a) => a.handle)
      } else {
        return arg
      }
  }
}

const serializeArguments = <T extends Record<string, Argument> = Record<string, Argument>>(
  args: T
): SerializedOptions<T> => {
  const retVal: SerializedArguments = {}
  Object.entries(args).forEach(([key, val]) => (retVal[key] = serialize(val)))
  return retVal as SerializedOptions<T>
}

export { serializeArguments }
