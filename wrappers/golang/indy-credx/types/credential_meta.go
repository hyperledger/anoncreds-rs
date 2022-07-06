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

type CredentialOffer struct {
	handle   ObjectHandle
	isClosed bool
}

func (c *CredentialOffer) getHandle() ObjectHandle {
	return c.handle
}

func NewCredentialOffer(schemaId string, credDef *CredentialDefinition, proof *KeyCorrectnessProof) (*CredentialOffer, error) {
	cSchemaId := C.CString(schemaId)
	var handle ObjectHandle

	err := C.credx_create_credential_offer(
		cSchemaId,
		(C.ulong)(credDef.handle),
		(C.ulong)(proof.handle),
		(*C.ulong)(&handle),
	)

	if err != 0 {
		context := fmt.Sprintf("Couldn't create CredentialOffer, received code %d", int(err))

		return nil, handleLibError(context)
	}

	credOffer := &CredentialOffer{
		handle: handle,
	}
	runtime.SetFinalizer(credOffer, func(credOffer *CredentialOffer) { credOffer.close() })

	return credOffer, nil
}

func (c *CredentialOffer) ToJSON() (json.RawMessage, error) {
	return genericToJSON(c)
}

func LoadCredentialOfferFromJSON(json json.RawMessage) (*CredentialOffer, error) {
	var handle ObjectHandle
	buf := ByteBufferFromRawMessage(json)

	err := C.credx_credential_offer_from_json((C.ByteBuffer)(buf), (*C.ulong)(&handle))

	if err != 0 {
		context := fmt.Sprintf("Couldn't create CredentialOffer from json, recevied code %d.", int(err))

		return nil, handleLibError(context)
	}

	credOffer := &CredentialOffer{
		handle: handle,
	}
	runtime.SetFinalizer(credOffer, func(credOffer *CredentialOffer) { credOffer.close() })

	return credOffer, nil
}

func (c *CredentialOffer) close() {
	if !c.isClosed {
		C.credx_object_free((C.ulong)(c.handle))
	}

	c.isClosed = true
}

type CredentialRequest struct {
	handle   ObjectHandle
	isClosed bool
}

func (c *CredentialRequest) getHandle() ObjectHandle {
	return c.handle
}

func NewCredentialRequest(
	proverDid string,
	credDef *CredentialDefinition,
	masterSecret *MasterSecret,
	masterSecretId string,
	credOffer *CredentialOffer,
) (*CredentialRequest, *CredentialRequestMetadata, error) {
	cDid := C.CString(proverDid)
	cMasterId := C.CString(masterSecretId)
	var credReqHandle ObjectHandle
	var credReqMetaHandle ObjectHandle

	err := C.credx_create_credential_request(
		cDid,
		(C.ulong)(credDef.handle),
		(C.ulong)(masterSecret.handle),
		cMasterId,
		(C.ulong)(credOffer.handle),
		(*C.ulong)(&credReqHandle),
		(*C.ulong)(&credReqMetaHandle),
	)

	if err != 0 {
		context := fmt.Sprintf("Couldn't create credReq, received code %d", int(err))

		return nil, nil, handleLibError(context)
	}

	credReq := &CredentialRequest{
		handle: credReqHandle,
	}
	credReqMetadata := &CredentialRequestMetadata{
		handle: credReqMetaHandle,
	}
	runtime.SetFinalizer(credReq, func(credReq *CredentialRequest) { credReq.close() })
	runtime.SetFinalizer(credReqMetadata, func(credReqMetadata *CredentialRequestMetadata) { credReqMetadata.close() })

	return credReq, credReqMetadata, nil
}

func (c *CredentialRequest) ToJSON() (json.RawMessage, error) {
	return genericToJSON(c)
}

func LoadCredentialRequestFromJSON(json json.RawMessage) (*CredentialRequest, error) {
	var handle ObjectHandle
	buf := ByteBufferFromRawMessage(json)

	err := C.credx_credential_request_from_json((C.ByteBuffer)(buf), (*C.ulong)(&handle))

	if err != 0 {
		context := fmt.Sprintf("Couldn't create CredentialRequest from json, recevied code %d.", int(err))

		return nil, handleLibError(context)
	}

	credentialRequest := &CredentialRequest{
		handle: handle,
	}
	runtime.SetFinalizer(credentialRequest, func(credentialRequest *CredentialRequest) { credentialRequest.close() })

	return credentialRequest, nil
}

func (c *CredentialRequest) close() {
	if !c.isClosed {
		C.credx_object_free((C.ulong)(c.handle))
	}

	c.isClosed = true
}

type CredentialRequestMetadata struct {
	handle   ObjectHandle
	isClosed bool
}

func (c *CredentialRequestMetadata) getHandle() ObjectHandle {
	return c.handle
}

func (c *CredentialRequestMetadata) ToJSON() (json.RawMessage, error) {
	return genericToJSON(c)
}

func LoadCredentialRequestMetadataFromJSON(json json.RawMessage) (*CredentialRequestMetadata, error) {
	var handle ObjectHandle
	buf := ByteBufferFromRawMessage(json)

	err := C.credx_credential_request_metadata_from_json((C.ByteBuffer)(buf), (*C.ulong)(&handle))

	if err != 0 {
		context := fmt.Sprintf("Couldn't create CredentialRequestMetadata from json, recevied code %d.", int(err))

		return nil, handleLibError(context)
	}

	credentialRequestMetadata := &CredentialRequestMetadata{
		handle: handle,
	}
	runtime.SetFinalizer(credentialRequestMetadata, func(credentialRequestMetadata *CredentialRequestMetadata) { credentialRequestMetadata.close() })

	return credentialRequestMetadata, nil
}

func (c *CredentialRequestMetadata) close() {
	if !c.isClosed {
		C.credx_object_free((C.ulong)(c.handle))
	}

	c.isClosed = true
}
