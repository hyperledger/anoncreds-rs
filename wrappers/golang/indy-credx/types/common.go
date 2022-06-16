package types

/*#cgo LDFLAGS: -lindy_credx
#include "../libindy_credx.h"
#include <stdlib.h>

*/
import "C"
import (
	"encoding/json"
	"fmt"
	"reflect"
	"unsafe"
)

func handleLibError(context string) error {
	var cArray StrBuffer
	defer CloseStrBuffer(cArray)

	err := C.credx_get_current_error(
		(**C.char)(&cArray),
	)

	if err != 0 {
		return fmt.Errorf("%s", context)
	}

	goArray := C.GoString(cArray)

	return fmt.Errorf("%s. The following error was encountered: %s", context, (string)(goArray))
}

// Generics are part of go 1.8, it might make sense to refactor some this code using generics

type ObjectHandle C.ulong

type StrBuffer *C.char

func CloseStrBuffer(buffer StrBuffer) {
	C.credx_string_free((*C.char)(buffer))
}

type ByteBuffer C.ByteBuffer

func NewByteBuffer(len int) ByteBuffer {
	cCount := C.uintptr_t(len)
	cArray := C.malloc(C.size_t(len))

	return ByteBuffer{
		len:   cCount,
		value: unsafe.Pointer(cArray),
	}
}

func ByteBufferFromRawMessage(json json.RawMessage) ByteBuffer {
	return ByteBuffer{
		len:   C.uintptr_t(len(json)),
		value: unsafe.Pointer(&json[0]),
	}
}

func (b ByteBuffer) ToGo() []byte {
	return C.GoBytes(b.value, (C.int)(b.len))
}

func (b ByteBuffer) ToC() *C.ByteBuffer {
	return (*C.ByteBuffer)(&b)
}

func (b ByteBuffer) Close() {
	C.credx_buffer_free((C.ByteBuffer)(b))
}

type FfiStr C.FfiStr
type FfiStrList C.FfiStrList

func NewFfiStrList(list []string) FfiStrList {
	cCount := C.uintptr_t(len(list))
	cArray := C.malloc(C.size_t(len(list)))

	a := (*[1 << 30]*C.char)(cArray)

	for index, item := range list {
		a[index] = C.CString(item)
	}

	return FfiStrList{
		count: cCount,
		data:  (*C.FfiStr)(cArray),
	}
}

func (b FfiStrList) Close() {
	C.free(unsafe.Pointer(b.data))
}

type FfiListI64 C.FfiList_i64

func NewFfiI64(list []int64) FfiListI64 {
	cCount := C.uintptr_t(len(list))
	cArray := C.malloc(C.size_t(len(list)))

	a := (*[1 << 30]C.int64_t)(cArray)

	for index, item := range list {
		a[index] = C.int64_t(item)
	}

	ffiList := FfiListI64{
		count: cCount,
		data:  (*C.int64_t)(cArray),
	}

	return ffiList
}

func (b FfiListI64) Close() {
	C.free(unsafe.Pointer(b.data))
}

type IndyObject interface {
	getHandle() ObjectHandle
	ToJSON() (json.RawMessage, error)
}

func genericToJSON(indyObject IndyObject) (json.RawMessage, error) {
	buf := NewByteBuffer(4096)
	defer buf.Close()

	if err := C.credx_object_get_json((C.ulong)(indyObject.getHandle()), (*C.ByteBuffer)(&buf)); err != 0 {
		objectType := reflect.TypeOf(indyObject).String()
		context := fmt.Sprintf("Couldn't get %s as json, received code %d", objectType, int(err))

		return nil, handleLibError(context)
	}

	credOffer := C.GoBytes(buf.value, (C.int)(buf.len))

	return credOffer, nil
}

type FfiListObjectHandle C.FfiList_ObjectHandle

func NewFfiListObjectHandle(list []ObjectHandle) FfiListObjectHandle {
	cCount := C.uintptr_t(len(list))
	cArray := C.malloc(C.size_t(len(list)))

	a := (*[1 << 30]C.ulong)(cArray)

	for index, item := range list {
		a[index] = (C.ulong)(item)
	}

	return FfiListObjectHandle{
		count: cCount,
		data:  (*C.ulong)(cArray),
	}
}

func (b FfiListObjectHandle) Close() {
	C.free(unsafe.Pointer(b.data))
}

type FfiListFfiCredentialEntry C.FfiList_FfiCredentialEntry

func NewFfiListFfiCredentialEntry(list []CredentialEntry) FfiListFfiCredentialEntry {
	cCount := C.uintptr_t(len(list))
	cArray := C.malloc(C.size_t(len(list)))

	a := (*[1 << 30]C.FfiCredentialEntry)(cArray)

	for index, item := range list {
		a[index] = (C.FfiCredentialEntry)(item.ToC())
	}

	return FfiListFfiCredentialEntry{
		count: cCount,
		data:  (*C.FfiCredentialEntry)(cArray),
	}
}

func (b FfiListFfiCredentialEntry) Close() {
	C.free(unsafe.Pointer(b.data))
}

type FfiListFfiCredentialProve C.FfiList_FfiCredentialProve

func NewFfiListFfiCredentialProve(list []CredentialProve) FfiListFfiCredentialProve {
	cCount := C.uintptr_t(len(list))
	cArray := C.malloc(C.size_t(len(list)))

	a := (*[1 << 30]C.FfiCredentialProve)(cArray)

	for index, item := range list {
		a[index] = (C.FfiCredentialProve)(item.ToC())
	}

	return FfiListFfiCredentialProve{
		count: cCount,
		data:  (*C.FfiCredentialProve)(cArray),
	}
}

func (b FfiListFfiCredentialProve) Close() {
	C.free(unsafe.Pointer(b.data))
}

type FfiListFfiRevocationEntry C.FfiList_FfiRevocationEntry

func NewFfiListFfiRevocationEntry(list []RevocationEntry) FfiListFfiRevocationEntry {
	cCount := C.uintptr_t(len(list))
	cArray := C.malloc(C.size_t(len(list)))

	a := (*[1 << 30]C.FfiRevocationEntry)(cArray)

	for index, item := range list {
		a[index] = (C.FfiRevocationEntry)(item.ToC())
	}

	return FfiListFfiRevocationEntry{
		count: cCount,
		data:  (*C.FfiRevocationEntry)(cArray),
	}
}

func (b FfiListFfiRevocationEntry) Close() {
	C.free(unsafe.Pointer(b.data))
}

func GenerateNonce() (*string, error) {
	var cArray StrBuffer
	defer CloseStrBuffer(cArray)

	err := C.credx_generate_nonce((**C.char)(&cArray))

	if err != 0 {
		context := fmt.Sprintf("Couldn't encode raw attributes, received code %d", (int)(err))

		return nil, handleLibError(context)
	}

	goArray := C.GoString(cArray)

	return &goArray, nil
}
