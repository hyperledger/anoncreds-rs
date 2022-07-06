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

type Credential struct {
	handle   ObjectHandle
	isClosed bool
}

func NewCredential(
	credDef *CredentialDefinition,
	credDefPvt *CredentialDefinitionPrivate,
	credOffer *CredentialOffer,
	credRequest *CredentialRequest,
	credentialRevocationInfo *CredentialRevocationInfo,
	attrNames []string,
	attrValues []string,
	attrEncoded []string,
) (*Credential, *RevocationRegistry, *RevocationRegistryDelta, error) {
	var credHandle ObjectHandle
	var revRegHandle ObjectHandle
	var revDeltaHandle ObjectHandle

	cAttrNames := NewFfiStrList(attrNames)
	cAttrRawValues := NewFfiStrList(attrValues)
	cAttrEnc := NewFfiStrList(attrEncoded)
	cCredRevInfo := credentialRevocationInfo.ToC()

	err := C.credx_create_credential(
		(C.ulong)(credDef.handle),
		(C.ulong)(credDefPvt.handle),
		(C.ulong)(credOffer.handle),
		(C.ulong)(credRequest.handle),
		(C.FfiStrList)(cAttrNames),
		(C.FfiStrList)(cAttrRawValues),
		(C.FfiStrList)(cAttrEnc),
		(*C.FfiCredRevInfo)(cCredRevInfo),
		(*C.ulong)(&credHandle),
		(*C.ulong)(&revRegHandle),
		(*C.ulong)(&revDeltaHandle),
	)

	if err != 0 {
		context := fmt.Sprintf("couldn't create credential, received code %d", (int)(err))

		return nil, nil, nil, handleLibError(context)
	}

	credential := &Credential{handle: credHandle}
	revReg := &RevocationRegistry{handle: revRegHandle}
	revDelta := &RevocationRegistryDelta{handle: revDeltaHandle}

	runtime.SetFinalizer(credential, func(credential *Credential) { credential.close() })
	runtime.SetFinalizer(revReg, func(revReg *RevocationRegistry) { revReg.close() })
	runtime.SetFinalizer(revDelta, func(revDelta *RevocationRegistryDelta) { revDelta.close() })

	return credential, revReg, revDelta, nil
}

func LoadCredentialFromJSON(json json.RawMessage) (*Credential, error) {
	var handle ObjectHandle
	buf := ByteBufferFromRawMessage(json)

	err := C.credx_credential_from_json((C.ByteBuffer)(buf), (*C.ulong)(&handle))

	if err != 0 {
		context := fmt.Sprintf("Couldn't create Credential from json, recevied code %d.", int(err))

		return nil, handleLibError(context)
	}

	credential := &Credential{
		handle: handle,
	}
	runtime.SetFinalizer(credential, func(credential *Credential) { credential.close() })

	return credential, nil
}

func (c *Credential) Process(
	metadata *CredentialRequestMetadata,
	secret *MasterSecret,
	definition *CredentialDefinition,
	registryDefinition *RevocationRegistryDefinition,
) (*Credential, error) {
	var credHandle ObjectHandle

	err := C.credx_process_credential(
		(C.ulong)(c.handle),
		(C.ulong)(metadata.handle),
		(C.ulong)(secret.handle),
		(C.ulong)(definition.handle),
		(C.ulong)(registryDefinition.handle),
		(*C.ulong)(&credHandle),
	)

	if err != 0 {
		context := fmt.Sprintf("Couldn't process credential, received code %d", (int)(err))

		return nil, handleLibError(context)
	}

	credential := &Credential{
		handle: credHandle,
	}
	runtime.SetFinalizer(credential, func(credential *Credential) { credential.close() })

	return credential, nil
}

func (c *Credential) getHandle() ObjectHandle {
	return c.handle
}

func (c *Credential) ToJSON() (json.RawMessage, error) {
	return genericToJSON(c)
}

func (c *Credential) GetSchemaID() (string, error) {
	return c.getCredentialAttr("schema_id")
}

func (c *Credential) GetCredentialDefinitionID() (string, error) {
	return c.getCredentialAttr("cred_def_id")
}

func (c *Credential) GetRevocationRegistryID() (string, error) {
	return c.getCredentialAttr("rev_reg_id")
}

func (c *Credential) GetRevocationRegistryIndex() (string, error) {
	return c.getCredentialAttr("rev_reg_index")
}

func (c *Credential) getCredentialAttr(attr string) (string, error) {
	var cArray StrBuffer
	defer CloseStrBuffer(cArray)

	err := C.credx_credential_get_attribute(
		(C.ulong)(c.handle),
		(C.FfiStr)(C.CString(attr)),
		(**C.char)(&cArray),
	)

	if err != 0 {
		context := fmt.Sprintf("Couldn't get Credential attributes, received code %d", (int)(err))

		return "", handleLibError(context)
	}

	goArray := C.GoString(cArray)

	return goArray, nil
}

func (c *Credential) close() {
	if !c.isClosed {
		C.credx_object_free((C.ulong)(c.handle))
	}

	c.isClosed = true
}

type CredentialRevocationState struct {
	handle   ObjectHandle
	isClosed bool
}

func NewCredentialRevocationState(
	registryDef *RevocationRegistryDefinition,
	registryDelta *RevocationRegistryDelta,
	credRevInfo *CredentialRevocationInfo,
	timestamp int64,
) (*CredentialRevocationState, error) {
	var handle ObjectHandle
	tails, tailsErr := registryDef.GetTailsLocation()

	if tailsErr != nil {
		return nil, tailsErr
	}

	err := C.credx_create_or_update_revocation_state(
		(C.ulong)(registryDef.handle),
		(C.ulong)(registryDelta.handle),
		C.int64_t(credRevInfo.regIdx),
		C.int64_t(timestamp),
		(*C.char)(C.CString(tails)),
		(C.ulong)(0),
		(*C.ulong)(&handle),
	)

	if err != 0 {
		context := fmt.Sprintf("Couldn't create credential revocation state, received code %d", (int)(err))

		return nil, handleLibError(context)
	}

	credRevState := &CredentialRevocationState{
		handle: handle,
	}

	runtime.SetFinalizer(credRevState, func(credRevState *CredentialRevocationState) { credRevState.close() })

	return credRevState, nil
}

func (p *CredentialRevocationState) Update(
	definition *RevocationRegistryDefinition,
	delta *RevocationRegistryDelta,
	revRegIndex int64,
	timestamp int64,
	tailsPath string,
) (*CredentialRevocationState, error) {
	var handle ObjectHandle

	err := C.credx_create_or_update_revocation_state(
		(C.ulong)(definition.handle),
		(C.ulong)(delta.handle),
		C.int64_t(revRegIndex),
		C.int64_t(timestamp),
		(*C.char)(C.CString(tailsPath)),
		(C.ulong)(p.handle),
		(*C.ulong)(&handle),
	)

	if err != 0 {
		context := fmt.Sprintf("Couldn't create credential revocation state, received code %d", (int)(err))

		return nil, handleLibError(context)
	}

	credRevState := &CredentialRevocationState{
		handle: handle,
	}

	runtime.SetFinalizer(credRevState, func(credRevState *CredentialRevocationState) { credRevState.close() })

	return credRevState, nil
}

func (p *CredentialRevocationState) close() {
	if !p.isClosed {
		C.credx_object_free((C.ulong)(p.handle))
	}
	p.isClosed = true
}
