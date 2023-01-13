/* eslint-disable @typescript-eslint/no-explicit-any */

import type { nativeBindings } from './bindings'

// We need a mapping from string type value => type (property 'string' maps to type string)
interface StringTypeMapping {
  pointer: Buffer
  'char*': Buffer
  string: string
  int64: number
  int32: number
  int8: number
  int: number
  size_t: number
}

// Needed so TS stops complaining about index signatures
type ShapeOf<T> = {
  [Property in keyof T]: T[Property]
}
type StringTypeArrayToTypes<List extends Array<keyof StringTypeMapping>> = {
  [Item in keyof List]: List[Item] extends keyof StringTypeMapping ? StringTypeMapping[List[Item]] : Buffer
}

type TypedMethods<Base extends { [method: string | number | symbol]: [any, any[]] }> = {
  [Property in keyof Base]: (
    ...args: StringTypeArrayToTypes<Base[Property][1]> extends any[] ? StringTypeArrayToTypes<Base[Property][1]> : []
  ) => StringTypeMapping[Base[Property][0]]
}
type Mutable<T> = {
  -readonly [K in keyof T]: Mutable<T[K]>
}

// TODO
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
export type NativeMethods = TypedMethods<ShapeOf<Mutable<typeof nativeBindings>>>
