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

type RevocationRegistryDefinition struct {
	handle   ObjectHandle
	isClosed bool
}

func (s *RevocationRegistryDefinition) getHandle() ObjectHandle {
	return s.handle
}

func (s *RevocationRegistryDefinition) ToJSON() (json.RawMessage, error) {
	return genericToJSON(s)

}

func (s *RevocationRegistryDefinition) close() {
	if !s.isClosed {
		C.credx_object_free((C.ulong)(s.handle))
	}

	s.isClosed = true
}

type RevocationRegistryDefinitionPrivate struct {
	handle   ObjectHandle
	isClosed bool
}

func (s *RevocationRegistryDefinitionPrivate) getHandle() ObjectHandle {
	return s.handle
}

func (s *RevocationRegistryDefinitionPrivate) ToJSON() (json.RawMessage, error) {
	return genericToJSON(s)
}

func (s *RevocationRegistryDefinitionPrivate) close() {
	if !s.isClosed {
		C.credx_object_free((C.ulong)(s.handle))
	}

	s.isClosed = true
}

type RevocationRegistryDelta struct {
	handle   ObjectHandle
	isClosed bool
}

func (s *RevocationRegistryDelta) getHandle() ObjectHandle {
	return s.handle
}

func (s *RevocationRegistryDelta) ToJSON() (json.RawMessage, error) {
	return genericToJSON(s)
}

func (s *RevocationRegistryDelta) close() {
	if !s.isClosed {
		C.credx_object_free((C.ulong)(s.handle))
	}

	s.isClosed = true
}

type RevocationRegistry struct {
	handle   ObjectHandle
	isClosed bool
}

func (s *RevocationRegistry) getHandle() ObjectHandle {
	return s.handle
}

func (s *RevocationRegistry) ToJSON() (json.RawMessage, error) {
	return genericToJSON(s)
}

func (s *RevocationRegistry) close() {
	if !s.isClosed {
		C.credx_object_free((C.ulong)(s.handle))
	}

	s.isClosed = true
}

type FfiCredentialRevocationInfo C.FfiCredRevInfo

type CredentialRevocationInfo struct {
	registryDefinition   *RevocationRegistryDefinition
	regDefinitionPrivate *RevocationRegistryDefinitionPrivate
	regEntry             *RevocationRegistry
	regIdx               int64
	regUsed              []int64
	tailsPath            string
}

func (c *CredentialRevocationInfo) ToC() *FfiCredentialRevocationInfo {
	cRegUsed := NewFfiI64(c.regUsed)
	cTailsPath := C.CString(c.tailsPath)

	return &FfiCredentialRevocationInfo{
		reg_def:         (C.ulong)(c.registryDefinition.handle),
		reg_def_private: (C.ulong)(c.regDefinitionPrivate.handle),
		registry:        (C.ulong)(c.regEntry.handle),
		reg_idx:         C.int64_t(c.regIdx),
		reg_used:        (C.FfiList_i64)(cRegUsed),
		tails_path:      (C.FfiStr)(cTailsPath),
	}
}

func NewRevocationRegistryDefinition(
	originDid string,
	credDef *CredentialDefinition,
	tag string,
	revRegType string,
	issuanceType string,
	maxCredNum int64,
	tailsDirPath string,
) (
	*RevocationRegistryDefinition,
	*RevocationRegistryDefinitionPrivate,
	*RevocationRegistry,
	*RevocationRegistryDelta,
	error,
) {
	cDid := C.CString(originDid)
	cTag := C.CString(tag)
	cRevRegType := C.CString(revRegType)
	var regDefHandle ObjectHandle
	var regDefPrivateHandle ObjectHandle
	var regEntryHandle ObjectHandle
	var regInitDeltaHandle ObjectHandle
	cIssuanceType := C.CString(issuanceType)
	cTailsDirPath := C.CString(tailsDirPath)

	if len(issuanceType) == 0 {
		cIssuanceType = nil
	}

	if len(tailsDirPath) == 0 {
		cTailsDirPath = nil
	}

	err := C.credx_create_revocation_registry(
		cDid,
		(C.ulong)(credDef.handle),
		cTag,
		cRevRegType,
		cIssuanceType,
		(C.int64_t)(maxCredNum),
		cTailsDirPath,
		(*C.ulong)(&regDefHandle),
		(*C.ulong)(&regDefPrivateHandle),
		(*C.ulong)(&regEntryHandle),
		(*C.ulong)(&regInitDeltaHandle),
	)

	if err != 0 {
		context := fmt.Sprintf("Couldn't create Revocastion Registry, received code %d", int(err))

		return nil, nil, nil, nil, handleLibError(context)
	}

	revReg := &RevocationRegistry{
		handle: regEntryHandle,
	}
	revRegDef := &RevocationRegistryDefinition{
		handle: regDefHandle,
	}
	revRegPrivate := &RevocationRegistryDefinitionPrivate{
		handle: regDefPrivateHandle,
	}
	revRegDelta := &RevocationRegistryDelta{
		handle: regInitDeltaHandle,
	}

	runtime.SetFinalizer(revReg, func(revReg *RevocationRegistry) { revReg.close() })
	runtime.SetFinalizer(revRegDef, func(revRegDef *RevocationRegistryDefinition) { revRegDef.close() })
	runtime.SetFinalizer(revRegPrivate, func(revRegPrivate *RevocationRegistryDefinitionPrivate) { revRegPrivate.close() })
	runtime.SetFinalizer(revRegDelta, func(revRegDelta *RevocationRegistryDelta) { revRegDelta.close() })

	return revRegDef, revRegPrivate, revReg, revRegDelta, nil
}

func LoadRevocationRegistryDefinitionFromJSON(json json.RawMessage) (*RevocationRegistryDefinition, error) {
	var handle ObjectHandle
	buf := ByteBufferFromRawMessage(json)

	err := C.credx_revocation_registry_definition_from_json((C.ByteBuffer)(buf), (*C.ulong)(&handle))

	if err != 0 {
		context := fmt.Sprintf("Couldn't create RevocationRegistryDefinition from json, recevied code %d.", int(err))

		return nil, handleLibError(context)
	}

	revocationRegistryDef := &RevocationRegistryDefinition{
		handle: handle,
	}
	runtime.SetFinalizer(revocationRegistryDef, func(revocationRegistryDef *RevocationRegistryDefinition) { revocationRegistryDef.close() })

	return revocationRegistryDef, nil
}

func LoadRevocationRegistryDefinitionPrivateFromJSON(json json.RawMessage) (*RevocationRegistryDefinitionPrivate, error) {
	var handle ObjectHandle
	buf := ByteBufferFromRawMessage(json)

	err := C.credx_revocation_registry_definition_private_from_json((C.ByteBuffer)(buf), (*C.ulong)(&handle))

	if err != 0 {
		context := fmt.Sprintf("Couldn't create RevocationRegistryDefinitionPrivate from json, recevied code %d.", int(err))

		return nil, handleLibError(context)
	}

	revocationRegistryDefPrivate := &RevocationRegistryDefinitionPrivate{
		handle: handle,
	}
	runtime.SetFinalizer(revocationRegistryDefPrivate, func(revocationRegistryDefPrivate *RevocationRegistryDefinitionPrivate) {
		revocationRegistryDefPrivate.close()
	})

	return revocationRegistryDefPrivate, nil
}

func LoadRevocationRegistryFromJSON(json json.RawMessage) (*RevocationRegistry, error) {
	var handle ObjectHandle
	buf := ByteBufferFromRawMessage(json)

	err := C.credx_revocation_registry_from_json((C.ByteBuffer)(buf), (*C.ulong)(&handle))

	if err != 0 {
		context := fmt.Sprintf("Couldn't create RevocationRegistry from json, recevied code %d.", int(err))

		return nil, handleLibError(context)
	}

	revReg := &RevocationRegistry{
		handle: handle,
	}
	runtime.SetFinalizer(revReg, func(revReg *RevocationRegistry) { revReg.close() })

	return revReg, nil
}

func LoadRevocationRegistryDeltaFromJSON(json json.RawMessage) (*RevocationRegistryDelta, error) {
	var handle ObjectHandle
	buf := ByteBufferFromRawMessage(json)

	err := C.credx_revocation_registry_delta_from_json((C.ByteBuffer)(buf), (*C.ulong)(&handle))

	if err != 0 {
		context := fmt.Sprintf("Couldn't create RevocationRegistryDelta from json, recevied code %d.", int(err))

		return nil, handleLibError(context)
	}

	revRegDelta := &RevocationRegistryDelta{
		handle: handle,
	}
	runtime.SetFinalizer(revRegDelta, func(revRegDelta *RevocationRegistryDelta) { revRegDelta.close() })

	return revRegDelta, nil
}

func (s *RevocationRegistry) RevokeCredential(
	revRegDefinition *RevocationRegistryDefinition,
	credRevIndex int64,
	tailsPath string,
) (*RevocationRegistryDelta, error) {
	var regEntryHandle ObjectHandle
	var regDeltaHandle ObjectHandle

	cTailsPath := C.CString(tailsPath)

	err := C.credx_revoke_credential(
		(C.ulong)(revRegDefinition.handle),
		(C.ulong)(s.handle),
		C.int64_t(credRevIndex),
		(C.FfiStr)(cTailsPath),
		(*C.ulong)(&regEntryHandle),
		(*C.ulong)(&regDeltaHandle),
	)

	if err != 0 {
		context := fmt.Sprintf("Couldn't update revocation registry, received code %d", (int)(err))

		return nil, handleLibError(context)
	}

	s.handle = regEntryHandle
	revRegDelta := &RevocationRegistryDelta{handle: regDeltaHandle}
	runtime.SetFinalizer(revRegDelta, func(revRegDelta *RevocationRegistryDelta) { revRegDelta.close() })

	return revRegDelta, nil
}

func (s *RevocationRegistry) Update(
	revRegDefinition *RevocationRegistryDefinition,
	issued []int64,
	revoked []int64,
	tailsPath string,
) (*RevocationRegistryDelta, error) {
	var regEntryHandle ObjectHandle
	var regDeltaHandle ObjectHandle

	cIssued := NewFfiI64(issued)
	cRevoked := NewFfiI64(revoked)
	cTailsPath := C.CString(tailsPath)

	err := C.credx_update_revocation_registry(
		(C.ulong)(revRegDefinition.handle),
		(C.ulong)(s.handle),
		(C.FfiList_i64)(cIssued),
		(C.FfiList_i64)(cRevoked),
		(C.FfiStr)(cTailsPath),
		(*C.ulong)(&regEntryHandle),
		(*C.ulong)(&regDeltaHandle),
	)

	if err != 0 {
		context := fmt.Sprintf("Couldn't update revocation registry, received code %d", (int)(err))

		return nil, handleLibError(context)
	}

	revocationRegistryDelta := &RevocationRegistryDelta{handle: regDeltaHandle}
	runtime.SetFinalizer(revocationRegistryDelta, func(revocationRegistryDelta RevocationRegistryDelta) { revocationRegistryDelta.close() })

	return revocationRegistryDelta, nil

}

func (s *RevocationRegistryDelta) UpdateWith(delta RevocationRegistryDelta) (*RevocationRegistryDelta, error) {
	var updatedDelta ObjectHandle

	err := C.credx_merge_revocation_registry_deltas(
		(C.ulong)(s.handle),
		(C.ulong)(delta.handle),
		(*C.ulong)(&updatedDelta),
	)

	if err != 0 {
		context := fmt.Sprintf("Couldn't update delta, recevied code %d.", int(err))

		return nil, handleLibError(context)
	}

	revocationRegistryDelta := &RevocationRegistryDelta{handle: updatedDelta}
	runtime.SetFinalizer(revocationRegistryDelta, func(revocationRegistryDelta RevocationRegistryDelta) { revocationRegistryDelta.close() })

	return revocationRegistryDelta, nil
}

func (s *RevocationRegistryDefinition) getAttr(attrName string) (string, error) {
	var cArray StrBuffer
	defer CloseStrBuffer(cArray)
	cAttrName := C.CString(attrName)

	err := C.credx_revocation_registry_definition_get_attribute(
		(C.ulong)(s.handle),
		(C.FfiStr)(cAttrName),
		(**C.char)(&cArray),
	)

	if err != 0 {
		context := fmt.Sprintf("Couldn't get attribute %s, received code %d", attrName, (int)(err))

		return "", handleLibError(context)
	}

	goString := C.GoString(cArray)

	return goString, nil
}

func (s *RevocationRegistryDefinition) GetID() (string, error) {
	return s.getAttr("id")
}

func (s *RevocationRegistryDefinition) GetMaxCredNum() (string, error) {
	return s.getAttr("max_cred_num")
}

func (s *RevocationRegistryDefinition) GetTailsHash() (string, error) {
	return s.getAttr("tails_hash")
}

func (s *RevocationRegistryDefinition) GetTailsLocation() (string, error) {
	return s.getAttr("tails_location")
}
