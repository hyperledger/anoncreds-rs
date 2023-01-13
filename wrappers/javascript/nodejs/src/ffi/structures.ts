import RefArray from 'ref-array-di'
import * as ref from 'ref-napi'
import RefStruct from 'ref-struct-di'

import { FFI_INT64, FFI_INT8, FFI_ISIZE, FFI_STRING } from './primitives'

const CStruct = RefStruct(ref)
const CArray = RefArray(ref)

export const StringArray = CArray('string')

const FFI_INT64_ARRAY = CArray('int64')
const FFI_INT64_ARRAY_PTR = ref.refType(FFI_INT64_ARRAY)

export const ByteBufferArray = CArray('uint8')
export const ByteBufferArrayPtr = ref.refType(FFI_STRING)

export const Int64Array = FFI_INT64_ARRAY

export const StringArrayPtr = ref.refType(StringArray)

export const ByteBufferStruct = CStruct({
  len: FFI_INT64,
  data: ByteBufferArrayPtr,
})

export const ByteBufferStructPtr = ref.refType(ByteBufferStruct)

export const StringListStruct = CStruct({
  count: ref.types.size_t,
  data: StringArray,
})

export const StringListStructPtr = ref.refType(StringListStruct)

export const I64ListStruct = CStruct({
  count: FFI_ISIZE,
  data: FFI_INT64_ARRAY_PTR,
})

export const CredRevInfoStruct = CStruct({
  reg_def: FFI_ISIZE,
  reg_def_private: FFI_ISIZE,
  registry: FFI_ISIZE,
  reg_idx: FFI_INT64,
  reg_used: I64ListStruct,
  tails_path: FFI_STRING,
})

export const CredentialEntryStruct = CStruct({
  credential: FFI_ISIZE,
  timestamp: FFI_INT64,
  rev_state: FFI_ISIZE,
})

export const CredentialEntryArray = CArray(CredentialEntryStruct)

export const CredentialEntryListStruct = CStruct({
  count: FFI_ISIZE,
  data: CredentialEntryArray,
})

export const CredentialProveStruct = CStruct({
  entry_idx: FFI_INT64,
  referent: FFI_STRING,
  is_predictable: FFI_INT8,
  reveal: FFI_INT8,
})

export const CredentialProveArray = CArray(CredentialProveStruct)

export const CredentialProveListStruct = CStruct({
  count: FFI_ISIZE,
  data: CredentialProveArray,
})

export const ObjectHandleArray = CArray('size_t')

export const ObjectHandleListStruct = CStruct({
  count: FFI_ISIZE,
  data: ObjectHandleArray,
})

export const RevocationEntryStruct = CStruct({
  def_entry_idx: FFI_INT64,
  entry: FFI_ISIZE,
  timestamp: FFI_INT64,
})

export const RevocationEntryArray = CArray(RevocationEntryStruct)

export const RevocationEntryListStruct = CStruct({
  count: FFI_ISIZE,
  data: RevocationEntryArray,
})
