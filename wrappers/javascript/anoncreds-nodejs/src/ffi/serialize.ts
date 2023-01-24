import type { ByteBufferStruct } from './structures'

import { ObjectHandle } from '@hyperledger/anoncreds-shared'
import { NULL } from 'ref-napi'

import { ObjectHandleListStruct, StringListStruct, I32ListStruct, Int32Array } from './structures'

type Argument =
  | Record<string, unknown>
  | Array<unknown>
  | Date
  | Uint8Array
  | SerializedArgument
  | boolean
  | ObjectHandle

type SerializedArgument = string | number | ArrayBuffer | Buffer | typeof StringListStruct

type SerializedArguments = Record<string, SerializedArgument>

export type SerializedOptions<Type> = Required<{
  [Property in keyof Type]: Type[Property] extends string
    ? string
    : Type[Property] extends number
    ? number
    : Type[Property] extends boolean
    ? number
    : Type[Property] extends boolean | undefined
    ? number
    : Type[Property] extends Record<string, unknown>
    ? string
    : Type[Property] extends Array<string>
    ? Buffer
    : Type[Property] extends Array<number>
    ? Buffer
    : Type[Property] extends Array<number> | undefined
    ? Buffer
    : Type[Property] extends Array<unknown> | undefined
    ? string
    : Type[Property] extends Record<string, unknown> | undefined
    ? string
    : Type[Property] extends Date
    ? number
    : Type[Property] extends Date | undefined
    ? number
    : Type[Property] extends string | undefined
    ? string
    : Type[Property] extends number | undefined
    ? number
    : Type[Property] extends Buffer
    ? Buffer
    : Type[Property] extends ObjectHandle
    ? number
    : Type[Property] extends ObjectHandle | undefined
    ? number
    : Type[Property] extends Uint8Array
    ? typeof ByteBufferStruct
    : Type[Property] extends Uint8Array | undefined
    ? typeof ByteBufferStruct
    : unknown
}>

// TODO: this method needs to be reworked.
// It is very messy
// cannot handle complex data structures well
const serialize = (arg: Argument): SerializedArgument => {
  switch (typeof arg) {
    case 'undefined':
      return NULL
    case 'boolean':
      return Number(arg)
    case 'string':
      return arg
    case 'number':
      return arg
    case 'function':
      return arg
    case 'object':
      if (arg instanceof ObjectHandle) {
        return arg.handle
      } else if (Array.isArray(arg)) {
        if (arg.every((it) => typeof it === 'string')) {
          // eslint-disable-next-line @typescript-eslint/ban-ts-comment
          // @ts-ignore
          return StringListStruct({ count: arg.length, data: arg })
        } else if (arg.every((it) => it instanceof ObjectHandle)) {
          // eslint-disable-next-line @typescript-eslint/ban-ts-comment
          // @ts-ignore
          return ObjectHandleListStruct({ count: arg.length, data: arg.map((item: ObjectHandle) => item.handle) })
        } else if (arg.every((it) => typeof it === 'number')) {
          // eslint-disable-next-line @typescript-eslint/ban-ts-comment
          // @ts-ignore
          return I32ListStruct({ count: arg.length, data: Int32Array(arg) })
        }
      }
      // TODO: add more serialization here for classes and uint8arrays
      return JSON.stringify(arg)
    default:
      throw new Error('could not serialize value')
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
