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

type CredentialDefinitionPrivate struct {
	handle   ObjectHandle
	isClosed bool
}

func (c *CredentialDefinitionPrivate) getHandle() ObjectHandle {
	return c.handle
}

func LoadCredentialDefinitionPrivateFromJSON(json json.RawMessage) (*CredentialDefinitionPrivate, error) {
	var handle ObjectHandle
	buf := ByteBufferFromRawMessage(json)

	err := C.credx_credential_definition_private_from_json((C.ByteBuffer)(buf), (*C.ulong)(&handle))

	if err != 0 {
		context := fmt.Sprintf("Couldn't create cred def private from json, recevied code %d.", int(err))

		return nil, handleLibError(context)
	}

	credDefPrivate := &CredentialDefinitionPrivate{
		handle: handle,
	}
	runtime.SetFinalizer(credDefPrivate, func(credDefPrivate *CredentialDefinitionPrivate) { credDefPrivate.close() })

	return credDefPrivate, nil
}

func (c *CredentialDefinitionPrivate) ToJSON() (json.RawMessage, error) {
	return genericToJSON(c)
}

func (c *CredentialDefinitionPrivate) close() {
	if !c.isClosed {
		C.credx_object_free((C.ulong)(c.handle))
	}

	c.isClosed = true
}

type KeyCorrectnessProof struct {
	handle   ObjectHandle
	isClosed bool
}

func (c *KeyCorrectnessProof) getHandle() ObjectHandle {
	return c.handle
}

func LoadKeyCorrectnessProofFromJSON(json json.RawMessage) (*KeyCorrectnessProof, error) {
	var handle ObjectHandle
	buf := ByteBufferFromRawMessage(json)

	err := C.credx_key_correctness_proof_from_json((C.ByteBuffer)(buf), (*C.ulong)(&handle))

	if err != 0 {
		context := fmt.Sprintf("Couldn't create cred def private from json, recevied code %d.", int(err))

		return nil, handleLibError(context)
	}

	keyProof := &KeyCorrectnessProof{
		handle: handle,
	}
	runtime.SetFinalizer(keyProof, func(keyProof *KeyCorrectnessProof) { keyProof.close() })

	return keyProof, nil
}

func (c *KeyCorrectnessProof) ToJSON() (json.RawMessage, error) {
	return genericToJSON(c)
}

func (c *KeyCorrectnessProof) close() {
	if !c.isClosed {
		C.credx_object_free((C.ulong)(c.handle))
	}

	c.isClosed = true
}

type CredentialDefinition struct {
	handle   ObjectHandle
	isClosed bool
}

func (c *CredentialDefinition) getHandle() ObjectHandle {
	return c.handle
}

func (c *CredentialDefinition) ToJSON() (json.RawMessage, error) {
	return genericToJSON(c)
}

func (c *CredentialDefinition) close() {
	if !c.isClosed {
		C.credx_object_free((C.ulong)(c.handle))
	}

	c.isClosed = true
}

func NewCredentialDefinition(
	originDid string,
	schema *Schema,
	tag string,
	signatureType string,
	supportRevocation bool,
) (*CredentialDefinition, *CredentialDefinitionPrivate, *KeyCorrectnessProof, error) {
	cDid := C.CString(originDid)
	cTag := C.CString(tag)
	cSignatureType := C.CString(signatureType)
	var credDefHandle ObjectHandle
	var credDefPvtHandle ObjectHandle
	var keyProofHandle ObjectHandle
	var cSupportRevocation C.int8_t

	if supportRevocation {
		cSupportRevocation = (C.int8_t)(1)
	} else {
		cSupportRevocation = (C.int8_t)(0)
	}

	err := C.credx_create_credential_definition(
		cDid,
		(C.ulong)(schema.handle),
		cTag,
		cSignatureType,
		cSupportRevocation,
		(*C.ulong)(&credDefHandle),
		(*C.ulong)(&credDefPvtHandle),
		(*C.ulong)(&keyProofHandle),
	)

	if err != 0 {
		context := fmt.Sprintf("Couldn't create Credential Definition, received code %d", int(err))

		return nil, nil, nil, handleLibError(context)
	}

	credDef := &CredentialDefinition{
		handle: credDefHandle,
	}
	credDefPvt := &CredentialDefinitionPrivate{
		handle: credDefPvtHandle,
	}
	keyCorrectnessProof := &KeyCorrectnessProof{
		handle: keyProofHandle,
	}

	runtime.SetFinalizer(keyCorrectnessProof, func(keyCorrectnessProof *KeyCorrectnessProof) { keyCorrectnessProof.close() })
	runtime.SetFinalizer(credDefPvt, func(credDefPvt *CredentialDefinitionPrivate) { credDefPvt.close() })
	runtime.SetFinalizer(credDef, func(credDef *CredentialDefinition) { credDef.close() })

	return credDef, credDefPvt, keyCorrectnessProof, nil
}

func LoadCredentialDefinitionFromJSON(json json.RawMessage) (*CredentialDefinition, error) {
	var handle ObjectHandle
	buf := ByteBufferFromRawMessage(json)

	err := C.credx_credential_definition_from_json((C.ByteBuffer)(buf), (*C.ulong)(&handle))

	if err != 0 {
		context := fmt.Sprintf("Couldn't create cred def from json, recevied code %d.", int(err))

		return nil, handleLibError(context)
	}

	credDef := &CredentialDefinition{
		handle: handle,
	}
	runtime.SetFinalizer(credDef, func(credDef *CredentialDefinition) { credDef.close() })

	return credDef, nil
}

func (c *CredentialDefinition) getCredDefAttribute(attr string) (string, error) {
	var cArray StrBuffer
	defer CloseStrBuffer(cArray)

	err := C.credx_credential_definition_get_attribute(
		(C.ulong)(c.handle),
		(C.FfiStr)(C.CString(attr)),
		(**C.char)(&cArray),
	)

	if err != 0 {
		context := fmt.Sprintf("Couldn't get cred def attributes, received code %d", (int)(err))

		return "", handleLibError(context)
	}

	goArray := C.GoString(cArray)

	return goArray, nil
}

func (c *CredentialDefinition) GetID() (string, error) {
	return c.getCredDefAttribute("id")
}

func (c *CredentialDefinition) GetSchemaID() (string, error) {
	return c.getCredDefAttribute("schema_id")
}
