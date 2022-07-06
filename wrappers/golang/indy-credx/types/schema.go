package types

/*#cgo LDFLAGS: -lindy_credx
#include "../libindy_credx.h"
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"runtime"
)

type Schema struct {
	handle   ObjectHandle
	isClosed bool
}

func (s *Schema) getHandle() ObjectHandle {
	return s.handle
}

func NewSchema(
	originDid string,
	schemaName string,
	schemaVersion string,
	attrs []string,
	seqNo int64,
) (*Schema, error) {
	var handle ObjectHandle
	cDid := C.CString(originDid)
	cSchemaName := C.CString(schemaName)
	cSchemaVersion := C.CString(schemaVersion)
	cSeqNo := C.int64_t(seqNo)
	cAttrs := NewFfiStrList(attrs)
	defer cAttrs.Close()

	err := C.credx_create_schema(
		cDid,
		cSchemaName,
		cSchemaVersion,
		(C.FfiStrList)(cAttrs),
		cSeqNo,
		(*C.ulong)(&handle),
	)

	if err != 0 {
		context := fmt.Sprintf("Couldn't create Schema, received code %d", (int)(err))

		return nil, handleLibError(context)
	}

	schema := &Schema{
		handle: handle,
	}
	runtime.SetFinalizer(schema, func(s *Schema) {
		s.close()
	})

	return schema, nil
}

func (s *Schema) ToJSON() (json.RawMessage, error) {
	return genericToJSON(s)
}

func LoadSchemaFromJSON(json json.RawMessage) (*Schema, error) {
	var handle ObjectHandle
	buf := ByteBufferFromRawMessage(json)

	err := C.credx_schema_from_json((C.ByteBuffer)(buf), (*C.ulong)(&handle))

	if err != 0 {
		context := fmt.Sprintf("Couldn't create schema from json, recevied code %d.", int(err))

		return nil, handleLibError(context)
	}

	schema := &Schema{
		handle: handle,
	}
	runtime.SetFinalizer(schema, func(s *Schema) {
		s.close()
	})

	return schema, nil
}

func (s *Schema) GetID() (string, error) {
	return s.getSchemaAttribute("id")
}

func (s *Schema) getSchemaAttribute(attr string) (string, error) {
	var cArray StrBuffer
	defer CloseStrBuffer(cArray)

	err := C.credx_schema_get_attribute(
		(C.ulong)(s.handle),
		(C.FfiStr)(C.CString(attr)),
		(**C.char)(&cArray),
	)

	if err != 0 {
		context := fmt.Sprintf("Couldn't get schema attributes, received code %d", (int)(err))

		return "", handleLibError(context)
	}

	goArray := C.GoString(cArray)

	return goArray, nil
}

func (s *Schema) close() {
	if !s.isClosed {
		C.credx_object_free((C.ulong)(s.handle))
	}

	s.isClosed = true
}
