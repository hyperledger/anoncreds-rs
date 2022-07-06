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

type MasterSecret struct {
	handle   ObjectHandle
	isClosed bool
}

func (c *MasterSecret) getHandle() ObjectHandle {
	return c.handle
}

func NewMasterSecret() (*MasterSecret, error) {
	var handle ObjectHandle
	err := C.credx_create_master_secret((*C.ulong)(&handle))

	if err != 0 {
		context := fmt.Sprintf("Couldn't create MasterSecret, received code %d", int(err))

		return nil, handleLibError(context)
	}

	masterSecret := &MasterSecret{
		handle: handle,
	}
	runtime.SetFinalizer(masterSecret, func(secret *MasterSecret) { secret.close() })

	return masterSecret, nil
}

func LoadMasterSecretFromJSON(json json.RawMessage) (*MasterSecret, error) {
	var handle ObjectHandle
	buf := ByteBufferFromRawMessage(json)

	err := C.credx_master_secret_from_json((C.ByteBuffer)(buf), (*C.ulong)(&handle))

	if err != 0 {
		context := fmt.Sprintf("Couldn't create master secret from json, recevied code %d.", int(err))

		return nil, handleLibError(context)
	}

	masterSecret := &MasterSecret{
		handle: handle,
	}
	runtime.SetFinalizer(masterSecret, func(secret *MasterSecret) { secret.close() })

	return masterSecret, nil
}

func (c *MasterSecret) ToJSON() (json.RawMessage, error) {
	return genericToJSON(c)
}

func (c *MasterSecret) close() {
	if !c.isClosed {
		C.credx_object_free((C.ulong)(c.handle))
	}
	c.isClosed = true
}
