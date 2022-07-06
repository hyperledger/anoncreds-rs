package types

import (
	"github.com/stretchr/testify/require"
	"strconv"
	"testing"
)

var (
	testSchema, _     = NewSchema(testDid, testSchemaName, testSchemaVersion, testAttrsNames, testSeqNo)
	testTag           = "tag"
	testSignatureType = "CL"
)

func Test_NewCredentialDefinition(t *testing.T) {
	credentialDef, credentialDefPrivate, keyCorrectnessProof, err := NewCredentialDefinition(
		testDid,
		testSchema,
		testTag,
		testSignatureType,
		false,
	)

	require.Nil(t, err)
	require.NotNil(t, credentialDef)
	require.NotNil(t, credentialDefPrivate)
	require.NotNil(t, keyCorrectnessProof)
}

func Test_CredDefGetID(t *testing.T) {
	credentialDef, _, _, err := NewCredentialDefinition(
		testDid,
		testSchema,
		testTag,
		testSignatureType,
		false,
	)
	expectedResponse := "55GkHamhTU1ZbTbV2ab9DE:3:CL:15:tag"
	id, err := credentialDef.GetID()

	require.Nil(t, err)
	require.NotNil(t, id)
	require.Equal(t, expectedResponse, id)
}

func Test_GetSchemaIDFromCredDef(t *testing.T) {
	credentialDef, _, _, err := NewCredentialDefinition(
		testDid,
		testSchema,
		testTag,
		testSignatureType,
		false,
	)
	expectedResponse := strconv.FormatInt(testSeqNo, 10)
	id, err := credentialDef.GetSchemaID()

	require.Nil(t, err)
	require.NotNil(t, id)
	require.Equal(t, expectedResponse, id)
}

func Test_JsonCredentialDefinition(t *testing.T) {
	originalCredentialDef, _, _, err := NewCredentialDefinition(
		testDid,
		testSchema,
		testTag,
		testSignatureType,
		false,
	)
	originalJson, err := originalCredentialDef.ToJSON()

	require.Nil(t, err)
	require.NotNil(t, originalJson)

	loadedCredentialDef, err := LoadCredentialDefinitionFromJSON(originalJson)
	require.Nil(t, err)
	require.NotNil(t, loadedCredentialDef)

	loadedJson, err := loadedCredentialDef.ToJSON()
	require.Nil(t, err)
	require.NotNil(t, loadedJson)

	require.JSONEq(t, string(originalJson), string(loadedJson))
}

func Test_JsonCredentialDefinitionPrivate(t *testing.T) {
	_, originalCredentialDefPrivate, _, err := NewCredentialDefinition(
		testDid,
		testSchema,
		testTag,
		testSignatureType,
		false,
	)
	originalJson, err := originalCredentialDefPrivate.ToJSON()

	require.Nil(t, err)
	require.NotNil(t, originalJson)

	loadedCredentialDefPrivate, err := LoadCredentialDefinitionPrivateFromJSON(originalJson)
	require.Nil(t, err)
	require.NotNil(t, loadedCredentialDefPrivate)

	loadedJson, err := loadedCredentialDefPrivate.ToJSON()
	require.Nil(t, err)
	require.NotNil(t, loadedJson)

	require.JSONEq(t, string(originalJson), string(loadedJson))
}

func Test_JsonKeyCorrectnessProof(t *testing.T) {
	_, _, originalKeyCorrectnessProof, err := NewCredentialDefinition(
		testDid,
		testSchema,
		testTag,
		testSignatureType,
		false,
	)
	originalJson, err := originalKeyCorrectnessProof.ToJSON()

	require.Nil(t, err)
	require.NotNil(t, originalJson)

	loadedKeyCorrectnessProof, err := LoadKeyCorrectnessProofFromJSON(originalJson)
	require.Nil(t, err)
	require.NotNil(t, loadedKeyCorrectnessProof)

	loadedJson, err := loadedKeyCorrectnessProof.ToJSON()
	require.Nil(t, err)
	require.NotNil(t, loadedJson)

	require.JSONEq(t, string(originalJson), string(loadedJson))
}

func Test_closeCredentialDefinitionAndFriends(t *testing.T) {
	credentialDef, credentialDefPrivate, keyCorrectnessProof, _ := NewCredentialDefinition(
		testDid,
		testSchema,
		testTag,
		testSignatureType,
		false,
	)

	credentialDef.close()
	require.True(t, credentialDef.isClosed)
	credentialDef.close()

	credentialDefPrivate.close()
	require.True(t, credentialDefPrivate.isClosed)
	credentialDefPrivate.close()

	keyCorrectnessProof.close()
	require.True(t, keyCorrectnessProof.isClosed)
	keyCorrectnessProof.close()
}
