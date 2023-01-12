import { default as ref, refType } from 'ref-napi'

// Primitives

export const FFI_ISIZE = 'size_t'
export const FFI_INT8 = 'int8'
export const FFI_INT64 = 'int64'
export const FFI_UINT = 'uint'
export const FFI_UINT8 = 'uint8'
export const FFI_ERRORCODE = FFI_UINT
export const FFI_OBJECT_HANDLE = FFI_ISIZE
export const FFI_VOID = ref.types.void
export const FFI_STRING = 'string'

// Pointers

export const FFI_ISIZE_PTR = refType(FFI_ISIZE)
export const FFI_INT8_PTR = refType(FFI_INT8)
export const FFI_OBJECT_HANDLE_PTR = refType(FFI_OBJECT_HANDLE)
export const FFI_STRING_PTR = refType(FFI_STRING)
