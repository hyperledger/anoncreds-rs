package types

import (
	"github.com/stretchr/testify/require"
	"testing"
)

var (
	testCredOffer, _                                                        = NewCredentialOffer(testSchemaId, testCredentialDef, testKeyCorrectnessProof)
	testCredReq, testCredDefReqMeta, _                                      = NewCredentialRequest(testDid, testCredentialDef, testMasterSecret, testMasterSecretId, testCredOffer)
	testRevRegDef, testRevRevDefPrivate, testRevReg, testRevRegDeltaInit, _ = NewRevocationRegistryDefinition(testDid, testCredentialDef, testTag, testRevRegType, testIssuanceType, testMaxCredNum, testTailsDirPath)
	testTailsPath, _                                                        = testRevRegDef.GetTailsLocation()
	testCredRevInfo                                                         = &CredentialRevocationInfo{
		registryDefinition:   testRevRegDef,
		regDefinitionPrivate: testRevRevDefPrivate,
		regEntry:             testRevReg,
		regIdx:               10,
		regUsed:              []int64{},
		tailsPath:            testTailsPath,
	}
	testCredential, _, testRevRegDelta, _ = NewCredential(
		testCredentialDef,
		testCredentialDefPrivate,
		testCredOffer,
		testCredReq,
		testCredRevInfo,
		testAttrsNames,
		testAttrsValues,
		[]string{},
	)
)

func Test_NewCredential(t *testing.T) {
	credential, revocationRegistry, revocationRegistryDelta, err := NewCredential(
		testCredentialDef,
		testCredentialDefPrivate,
		testCredOffer,
		testCredReq,
		testCredRevInfo,
		testAttrsNames,
		testAttrsValues,
		[]string{},
	)

	require.Nil(t, err)
	require.NotNil(t, credential)
	require.NotNil(t, revocationRegistry)
	require.NotNil(t, revocationRegistryDelta)
}

func Test_CredentialJson(t *testing.T) {
	credential, _, _, err := NewCredential(
		testCredentialDef,
		testCredentialDefPrivate,
		testCredOffer,
		testCredReq,
		testCredRevInfo,
		testAttrsNames,
		testAttrsValues,
		[]string{},
	)
	require.Nil(t, err)

	originalCredentialJson, err := credential.ToJSON()
	require.Nil(t, err)

	loadedCredential, err := LoadCredentialFromJSON(originalCredentialJson)
	require.Nil(t, err)

	loadedCredentialJson, err := loadedCredential.ToJSON()
	require.Nil(t, err)

	require.JSONEq(t, string(originalCredentialJson), string(loadedCredentialJson))
}

func Test_GetCredentialAttrs(t *testing.T) {
	credential, _, _, err := NewCredential(
		testCredentialDef,
		testCredentialDefPrivate,
		testCredOffer,
		testCredReq,
		testCredRevInfo,
		testAttrsNames,
		testAttrsValues,
		[]string{},
	)
	require.Nil(t, err)

	schemaId, err := credential.GetSchemaID()
	require.Nil(t, err)
	require.NotNil(t, schemaId)

	credDefId, err := credential.GetCredentialDefinitionID()
	require.Nil(t, err)
	require.NotNil(t, credDefId)

	revRegId, err := credential.GetRevocationRegistryID()
	require.Nil(t, err)
	require.NotNil(t, revRegId)

	revRegIndex, err := credential.GetRevocationRegistryIndex()
	require.Nil(t, err)
	require.NotNil(t, revRegIndex)
}

func Test_ProcessCredential(t *testing.T) {
	credRevInfo := &CredentialRevocationInfo{
		registryDefinition:   testRevRegDef,
		regDefinitionPrivate: testRevRevDefPrivate,
		regEntry:             testRevReg,
		regIdx:               1,
		regUsed:              []int64{},
		tailsPath:            testTailsPath,
	}
	credential, _, _, err := NewCredential(
		testCredentialDef,
		testCredentialDefPrivate,
		testCredOffer,
		testCredReq,
		credRevInfo,
		testAttrsNames,
		testAttrsValues,
		[]string{},
	)

	credential, err = credential.Process(testCredDefReqMeta, testMasterSecret, testCredentialDef, testRevRegDef)
	require.Nil(t, err)
	require.NotNil(t, credential)
}

func Test_closeCredential(t *testing.T) {
	testRegIdx := int64(3)
	credRevInfo := &CredentialRevocationInfo{
		registryDefinition:   testRevRegDef,
		regDefinitionPrivate: testRevRevDefPrivate,
		regEntry:             testRevReg,
		regIdx:               testRegIdx,
		regUsed:              []int64{},
		tailsPath:            testTailsPath,
	}
	credential, _, _, _ := NewCredential(
		testCredentialDef,
		testCredentialDefPrivate,
		testCredOffer,
		testCredReq,
		credRevInfo,
		testAttrsNames,
		testAttrsValues,
		[]string{},
	)

	credential.close()
	require.True(t, credential.isClosed)
	credential.close() // should not panic
}
