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

type FfiCredentialEntry C.FfiCredentialEntry
type FfiCredentialProve C.FfiCredentialProve
type FfiRevocationEntry C.FfiRevocationEntry

type CredentialEntry struct {
	credential *Credential
	timestamp  int64
	revState   *CredentialRevocationState
}

func (c *CredentialEntry) ToC() FfiCredentialEntry {
	return FfiCredentialEntry{
		credential: (C.ulong)(c.credential.handle),
		timestamp:  C.int64_t(c.timestamp),
		rev_state:  (C.ulong)(c.revState.handle),
	}
}

type CredentialProve struct {
	entryIndex  int64
	referent    string
	isPredicate bool
	reveal      bool
}

func (c CredentialProve) ToC() FfiCredentialProve {
	cIsPredicate := int8(0)
	cReveal := int8(0)

	if c.isPredicate {
		cIsPredicate = int8(1)
	}

	if c.reveal {
		cReveal = int8(1)
	}

	return FfiCredentialProve{
		entry_idx:    C.int64_t(c.entryIndex),
		referent:     C.CString(c.referent),
		is_predicate: C.int8_t(cIsPredicate),
		reveal:       C.int8_t(cReveal),
	}

}

type RevocationEntry struct {
	defEntryIndex int64
	revReg        *RevocationRegistry
	timestamp     int64
}

func (r RevocationEntry) ToC() FfiRevocationEntry {
	return FfiRevocationEntry{
		def_entry_idx: C.int64_t(r.defEntryIndex),
		entry:         (C.ulong)(r.revReg.handle),
		timestamp:     C.int64_t(r.timestamp),
	}
}

type PresentationRequest struct {
	handle   ObjectHandle
	isClosed bool
}

type Presentation struct {
	handle   ObjectHandle
	isClosed bool
}

func NewPresentation(
	presentationRequest *PresentationRequest,
	credEntries []CredentialEntry,
	credProves []CredentialProve,
	selfAttestedAttrNames []string,
	selfAttestedAttrValues []string,
	masterSecret *MasterSecret,
	schemas []Schema,
	credDefs []CredentialDefinition,
) (*Presentation, error) {
	var handle ObjectHandle
	var schemaHandles []ObjectHandle
	var credDefHandles []ObjectHandle

	for _, schema := range schemas {
		schemaHandles = append(schemaHandles, schema.handle)
	}

	for _, credDef := range credDefs {
		credDefHandles = append(credDefHandles, credDef.handle)
	}

	cCredEntries := NewFfiListFfiCredentialEntry(credEntries)
	cCredProves := NewFfiListFfiCredentialProve(credProves)
	cSelfAttestedAttrNames := NewFfiStrList(selfAttestedAttrNames)
	cSelfAttestedAttrValues := NewFfiStrList(selfAttestedAttrValues)
	cSchemaHandles := NewFfiListObjectHandle(schemaHandles)
	cCredDefHandles := NewFfiListObjectHandle(credDefHandles)

	err := C.credx_create_presentation(
		(C.ulong)(presentationRequest.handle),
		(C.FfiList_FfiCredentialEntry)(cCredEntries),
		(C.FfiList_FfiCredentialProve)(cCredProves),
		(C.FfiStrList)(cSelfAttestedAttrNames),
		(C.FfiStrList)(cSelfAttestedAttrValues),
		(C.ulong)(masterSecret.handle),
		(C.FfiList_ObjectHandle)(cSchemaHandles),
		(C.FfiList_ObjectHandle)(cCredDefHandles),
		(*C.ulong)(&handle),
	)

	if err != 0 {
		context := fmt.Sprintf("Couldn't create presentation, received code %d", (int)(err))

		return nil, handleLibError(context)
	}

	presentation := &Presentation{
		handle: handle,
	}

	runtime.SetFinalizer(presentation, func(presentation *Presentation) { presentation.close() })

	return presentation, nil
}

func LoadPresentationFromJSON(json json.RawMessage) (*Presentation, error) {
	var handle ObjectHandle
	buf := ByteBufferFromRawMessage(json)

	err := C.credx_presentation_from_json((C.ByteBuffer)(buf), (*C.ulong)(&handle))

	if err != 0 {
		context := fmt.Sprintf("Couldn't create Presentation from json, recevied code %d.", int(err))

		return nil, handleLibError(context)
	}

	presentation := &Presentation{
		handle: handle,
	}
	runtime.SetFinalizer(presentation, func(presentation *Presentation) { presentation.close() })

	return presentation, nil
}

func (c *Presentation) getHandle() ObjectHandle {
	return c.handle
}

func (c *Presentation) ToJSON() (json.RawMessage, error) {
	return genericToJSON(c)
}

func (c *Presentation) Verify(
	presReq *PresentationRequest,
	schemas []Schema,
	credDefs []CredentialDefinition,
	regs []RevocationRegistryDefinition,
	revEntries []RevocationEntry,
) (bool, error) {
	var result int8
	var schemaHandles []ObjectHandle
	var credDefHandles []ObjectHandle
	var regDefHandles []ObjectHandle

	for _, schema := range schemas {
		schemaHandles = append(schemaHandles, schema.handle)
	}

	for _, credDef := range credDefs {
		credDefHandles = append(credDefHandles, credDef.handle)
	}

	for _, regDef := range regs {
		regDefHandles = append(regDefHandles, regDef.handle)
	}

	cSchemaHandles := NewFfiListObjectHandle(schemaHandles)
	cCredDefHandles := NewFfiListObjectHandle(credDefHandles)
	cRegDefHandles := NewFfiListObjectHandle(regDefHandles)
	cRevEntries := NewFfiListFfiRevocationEntry(revEntries)

	err := C.credx_verify_presentation(
		(C.ulong)(c.handle),
		(C.ulong)(presReq.handle),
		(C.FfiList_ObjectHandle)(cSchemaHandles),
		(C.FfiList_ObjectHandle)(cCredDefHandles),
		(C.FfiList_ObjectHandle)(cRegDefHandles),
		(C.FfiList_FfiRevocationEntry)(cRevEntries),
		(*C.int8_t)(&result),
	)

	if err != 0 {
		context := fmt.Sprintf("Couldn't verify presentation, received code %d", (int)(err))

		return false, handleLibError(context)
	}

	return result != 0, nil
}

func (c *Presentation) close() {
	if !c.isClosed {
		C.credx_object_free((C.ulong)(c.handle))
	}
	c.isClosed = true
}

func PresentationRequestFromJSON(json json.RawMessage) (*PresentationRequest, error) {
	var handle ObjectHandle
	cJson := ByteBufferFromRawMessage(json)

	err := C.credx_presentation_request_from_json(
		(C.ByteBuffer)(cJson),
		(*C.ulong)(&handle),
	)

	if err != 0 {
		context := fmt.Sprintf("Couldn't load presentation req from json, received code %d", (int)(err))

		return nil, handleLibError(context)
	}

	return &PresentationRequest{
		handle: handle,
	}, nil
}
