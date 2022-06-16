package types

import (
	"github.com/stretchr/testify/require"
	"testing"
)

var (
	testMasterSecretId                                                      = "test_123"
	testMasterSecret, _                                                     = NewMasterSecret()
	testSchemaId, _                                                         = testSchema.GetID()
	testCredentialDef, testCredentialDefPrivate, testKeyCorrectnessProof, _ = NewCredentialDefinition(
		testDid,
		testSchema,
		testTag,
		testSignatureType,
		true,
	)
)

func Test_NewCredentialOffer(t *testing.T) {
	credentialOffer, err := NewCredentialOffer(testSchemaId, testCredentialDef, testKeyCorrectnessProof)

	require.Nil(t, err)
	require.NotNil(t, credentialOffer)
}

func Test_JsonCredentialOffer(t *testing.T) {
	originalCredentialOffer, err := NewCredentialOffer(testSchemaId, testCredentialDef, testKeyCorrectnessProof)

	originalJson, err := originalCredentialOffer.ToJSON()

	require.Nil(t, err)
	require.NotNil(t, originalJson)

	loadedCredentialOffer, err := LoadCredentialOfferFromJSON(originalJson)
	require.Nil(t, err)
	require.NotNil(t, loadedCredentialOffer)

	loadedJson, err := loadedCredentialOffer.ToJSON()
	require.Nil(t, err)
	require.NotNil(t, loadedJson)

	require.JSONEq(t, string(originalJson), string(loadedJson))
}

func Test_closeCredentialOffer(t *testing.T) {
	originalCredentialOffer, _ := NewCredentialOffer(testSchemaId, testCredentialDef, testKeyCorrectnessProof)

	originalCredentialOffer.close()
	require.True(t, originalCredentialOffer.isClosed)
	originalCredentialOffer.close() // should not panic
}

func Test_NewCredentialRequest(t *testing.T) {
	credentialOffer, _ := NewCredentialOffer(testSchemaId, testCredentialDef, testKeyCorrectnessProof)
	credentialRequest, credentialRequestMetadata, err := NewCredentialRequest(
		testDid,
		testCredentialDef,
		testMasterSecret,
		testMasterSecretId,
		credentialOffer,
	)

	require.Nil(t, err)
	require.NotNil(t, credentialRequest)
	require.NotNil(t, credentialRequestMetadata)

}

func Test_JsonCredentialRequest(t *testing.T) {
	credentialOffer, _ := NewCredentialOffer(testSchemaId, testCredentialDef, testKeyCorrectnessProof)
	originalCredentialRequest, originalCredentialRequestMetadata, _ := NewCredentialRequest(
		testDid,
		testCredentialDef,
		testMasterSecret,
		testMasterSecretId,
		credentialOffer,
	)

	originalJson, err := originalCredentialRequest.ToJSON()
	originalMetadataJson, err := originalCredentialRequestMetadata.ToJSON()

	require.Nil(t, err)
	require.NotNil(t, originalJson)
	require.NotNil(t, originalMetadataJson)

	loadedCredentialRequest, err := LoadCredentialRequestFromJSON(originalJson)
	require.Nil(t, err)
	require.NotNil(t, loadedCredentialRequest)

	loadedCredentialRequestMetadata, err := LoadCredentialRequestMetadataFromJSON(originalMetadataJson)
	require.Nil(t, err)
	require.NotNil(t, loadedCredentialRequestMetadata)

	loadedJson, err := loadedCredentialRequest.ToJSON()
	require.Nil(t, err)
	require.NotNil(t, loadedJson)

	loadedMetadataJson, err := loadedCredentialRequestMetadata.ToJSON()
	require.Nil(t, err)
	require.NotNil(t, loadedJson)

	require.JSONEq(t, string(originalJson), string(loadedJson))
	require.JSONEq(t, string(originalMetadataJson), string(loadedMetadataJson))
}

func Test_closeCredentialRequest(t *testing.T) {
	credentialOffer, _ := NewCredentialOffer(testSchemaId, testCredentialDef, testKeyCorrectnessProof)
	credentialRequest, credentialRequestMetadata, _ := NewCredentialRequest(
		testDid,
		testCredentialDef,
		testMasterSecret,
		testMasterSecretId,
		credentialOffer,
	)

	credentialRequest.close()
	require.True(t, credentialRequest.isClosed)
	credentialRequest.close() // should not panic

	credentialRequestMetadata.close()
	require.True(t, credentialRequestMetadata.isClosed)
	credentialRequestMetadata.close() // should not panic
}
