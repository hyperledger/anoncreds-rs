package types

import (
	"github.com/stretchr/testify/require"
	"strconv"
	"testing"
)

var (
	testRevRegTag    = "default"
	testRevRegType   = "CL_ACCUM"
	testMaxCredNum   = int64(100)
	testTailsDirPath = ""
	testIssuanceType = ""
)

func Test_NewRevocationRegistryDefinition(t *testing.T) {
	revRegDef, revRegDefPrivate, revReg, revRegDelta, err := NewRevocationRegistryDefinition(
		testDid,
		testCredentialDef,
		testRevRegTag,
		testRevRegType,
		testIssuanceType,
		testMaxCredNum,
		testTailsDirPath,
	)

	require.Nil(t, err)
	require.NotNil(t, revRegDef)
	require.NotNil(t, revRegDefPrivate)
	require.NotNil(t, revReg)
	require.NotNil(t, revRegDelta)
}

func Test_JsonRevocationRegistry(t *testing.T) {
	revRegDef, revRegDefPrivate, revReg, revRegDelta, _ := NewRevocationRegistryDefinition(
		testDid,
		testCredentialDef,
		testRevRegTag,
		testRevRegType,
		testIssuanceType,
		testMaxCredNum,
		testTailsDirPath,
	)

	revRegOriginalJson, err := revReg.ToJSON()
	require.Nil(t, err)

	revRegDefOriginalJson, err := revRegDef.ToJSON()
	require.Nil(t, err)

	revRegDefPrivateOriginalJson, err := revRegDefPrivate.ToJSON()
	require.Nil(t, err)

	revRegDeltaOriginalJson, err := revRegDelta.ToJSON()
	require.Nil(t, err)

	require.NotNil(t, revRegOriginalJson)
	require.NotNil(t, revRegDefOriginalJson)
	require.NotNil(t, revRegDefPrivateOriginalJson)
	require.NotNil(t, revRegDeltaOriginalJson)

	loadedRevRegDef, err := LoadRevocationRegistryDefinitionFromJSON(revRegDefOriginalJson)
	require.Nil(t, err)
	require.NotNil(t, loadedRevRegDef)

	loadedRevReg, err := LoadRevocationRegistryFromJSON(revRegOriginalJson)
	require.Nil(t, err)
	require.NotNil(t, loadedRevReg)

	loadedRevRegDelta, err := LoadRevocationRegistryDeltaFromJSON(revRegDeltaOriginalJson)
	require.Nil(t, err)
	require.NotNil(t, loadedRevRegDelta)

	loadedRevRegDefPrivate, err := LoadRevocationRegistryDefinitionPrivateFromJSON(revRegDefPrivateOriginalJson)
	require.Nil(t, err)
	require.NotNil(t, loadedRevRegDefPrivate)

	loadedRevRegJson, err := loadedRevReg.ToJSON()
	require.Nil(t, err)
	require.NotNil(t, loadedRevRegJson)

	loadedRevRegDefJson, err := loadedRevRegDef.ToJSON()
	require.Nil(t, err)
	require.NotNil(t, loadedRevRegDefJson)

	loadedRevRegDeltaJson, err := loadedRevRegDelta.ToJSON()
	require.Nil(t, err)
	require.NotNil(t, loadedRevRegDeltaJson)

	loadedRevRegDefPrivateJson, err := loadedRevRegDefPrivate.ToJSON()
	require.Nil(t, err)
	require.NotNil(t, loadedRevRegDefPrivateJson)

	require.JSONEq(t, string(revRegOriginalJson), string(loadedRevRegJson))
	require.JSONEq(t, string(revRegDefOriginalJson), string(loadedRevRegDefJson))
	require.JSONEq(t, string(revRegDefPrivateOriginalJson), string(loadedRevRegDefPrivateJson))
}

func Test_GetRevRegAttrs(t *testing.T) {
	revRegDef, _, _, _, _ := NewRevocationRegistryDefinition(
		testDid,
		testCredentialDef,
		testRevRegTag,
		testRevRegType,
		testIssuanceType,
		testMaxCredNum,
		testTailsDirPath,
	)

	id, err := revRegDef.GetID()
	require.Nil(t, err)
	require.NotNil(t, id)

	maxCredNum, err := revRegDef.GetMaxCredNum()
	require.Nil(t, err)
	require.NotNil(t, maxCredNum)
	require.Equal(t, strconv.FormatInt(testMaxCredNum, 10), maxCredNum)

	tailsLocation, err := revRegDef.GetTailsLocation()
	require.Nil(t, err)
	require.NotNil(t, tailsLocation)

	tailsHash, err := revRegDef.GetTailsHash()
	require.Nil(t, err)
	require.NotNil(t, tailsHash)
}

func Test_closeRevocationRegistry(t *testing.T) {
	revRegDef, revRegDefPrivate, revReg, revRegDelta, _ := NewRevocationRegistryDefinition(
		testDid,
		testCredentialDef,
		testRevRegTag,
		testRevRegType,
		testIssuanceType,
		testMaxCredNum,
		testTailsDirPath,
	)

	revRegDef.close()
	require.True(t, revRegDef.isClosed)
	revRegDef.close() // should not panic

	revRegDefPrivate.close()
	require.True(t, revRegDefPrivate.isClosed)
	revRegDefPrivate.close() // should not panic

	revReg.close()
	require.True(t, revReg.isClosed)
	revReg.close() // should not panic

	revRegDelta.close()
	require.True(t, revRegDelta.isClosed)
	revRegDelta.close() // should not panic
}
