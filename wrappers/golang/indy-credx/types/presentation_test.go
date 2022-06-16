package types

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

var (
	testTimestamp           = time.Now().Unix()
	testNonce, _            = GenerateNonce()
	testReferent            = "reft"
	testPresentationReqJson = []byte(
		fmt.Sprintf(
			`{"name":"proof","version":"1.0","nonce":"%d","requested_attributes":{"%s":{"name":"attr","non_revoked":{"from":%d,"to":%d}}},"requested_predicates":{},"non_revoked":{"from":%d,"to":%d},"ver":"1.0"}`,
			testNonce,
			testReferent,
			testTimestamp,
			testTimestamp,
			testTimestamp,
			testTimestamp),
	)
)

func Test_NewPresentation(t *testing.T) {
	processedCredential, err := testCredential.Process(testCredDefReqMeta, testMasterSecret, testCredentialDef, testRevRegDef)
	require.Nil(t, err)

	presentationReq, err := PresentationRequestFromJSON(testPresentationReqJson)
	require.Nil(t, err)

	credRevState, err := NewCredentialRevocationState(testRevRegDef, testRevRegDeltaInit, testCredRevInfo, testTimestamp)
	require.Nil(t, err)

	credentialEntries := []CredentialEntry{{
		credential: processedCredential,
		timestamp:  testTimestamp,
		revState:   credRevState,
	}}

	credentialProves := []CredentialProve{{
		entryIndex:  0,
		referent:    testReferent,
		isPredicate: false,
		reveal:      true,
	}}

	presentation, err := NewPresentation(
		presentationReq,
		credentialEntries,
		credentialProves,
		[]string{},
		[]string{},
		testMasterSecret,
		[]Schema{*testSchema},
		[]CredentialDefinition{*testCredentialDef},
	)

	require.Nil(t, err)
	require.NotNil(t, presentation)
}

func Test_VerifyPresentation(t *testing.T) {
	processedCredential, err := testCredential.Process(testCredDefReqMeta, testMasterSecret, testCredentialDef, testRevRegDef)
	require.Nil(t, err)

	presentationReq, err := PresentationRequestFromJSON(testPresentationReqJson)
	require.Nil(t, err)

	credRevState, err := NewCredentialRevocationState(testRevRegDef, testRevRegDeltaInit, testCredRevInfo, testTimestamp)
	require.Nil(t, err)

	credentialEntries := []CredentialEntry{{
		credential: processedCredential,
		timestamp:  testTimestamp,
		revState:   credRevState,
	}}

	credentialProves := []CredentialProve{{
		entryIndex:  0,
		referent:    testReferent,
		isPredicate: false,
		reveal:      true,
	}}

	presentation, err := NewPresentation(
		presentationReq,
		credentialEntries,
		credentialProves,
		[]string{},
		[]string{},
		testMasterSecret,
		[]Schema{*testSchema},
		[]CredentialDefinition{*testCredentialDef},
	)

	require.Nil(t, err)
	require.NotNil(t, presentation)

	revEntry := RevocationEntry{
		defEntryIndex: int64(0),
		revReg:        testRevReg,
		timestamp:     testTimestamp,
	}

	isValid, err := presentation.Verify(
		presentationReq,
		[]Schema{*testSchema},
		[]CredentialDefinition{*testCredentialDef},
		[]RevocationRegistryDefinition{*testRevRegDef},
		[]RevocationEntry{revEntry},
	)

	require.Nil(t, err)
	require.True(t, isValid)

	// we revoke the credential
	revRegDelta, err := testRevReg.RevokeCredential(testRevRegDef, 10, testTailsPath)
	require.Nil(t, err)
	require.NotNil(t, revRegDelta)

	updatedCredRevState, err := credRevState.Update(testRevRegDef, revRegDelta, 10, testTimestamp, testTailsPath)
	require.Nil(t, err)
	require.NotNil(t, updatedCredRevState)

	credentialEntries = []CredentialEntry{{
		credential: processedCredential,
		timestamp:  testTimestamp,
		revState:   updatedCredRevState,
	}}

	isValid, err = presentation.Verify(
		presentationReq,
		[]Schema{*testSchema},
		[]CredentialDefinition{*testCredentialDef},
		[]RevocationRegistryDefinition{*testRevRegDef},
		[]RevocationEntry{revEntry},
	)
	require.Nil(t, err)
	require.False(t, isValid) // the credential is revoked, the presentation shouldn't be valid
}

func Test_PresentationJson(t *testing.T) {
	processedCredential, err := testCredential.Process(testCredDefReqMeta, testMasterSecret, testCredentialDef, testRevRegDef)
	require.Nil(t, err)

	presentationReq, err := PresentationRequestFromJSON(testPresentationReqJson)
	require.Nil(t, err)

	credRevState, err := NewCredentialRevocationState(testRevRegDef, testRevRegDeltaInit, testCredRevInfo, testTimestamp)
	require.Nil(t, err)

	credentialEntries := []CredentialEntry{{
		credential: processedCredential,
		timestamp:  testTimestamp,
		revState:   credRevState,
	}}

	credentialProves := []CredentialProve{{
		entryIndex:  0,
		referent:    testReferent,
		isPredicate: false,
		reveal:      true,
	}}

	presentation, err := NewPresentation(
		presentationReq,
		credentialEntries,
		credentialProves,
		[]string{},
		[]string{},
		testMasterSecret,
		[]Schema{*testSchema},
		[]CredentialDefinition{*testCredentialDef},
	)

	require.Nil(t, err)
	require.NotNil(t, presentation)

	originalJson, err := presentation.ToJSON()
	require.Nil(t, err)
	require.NotNil(t, originalJson)

	loadedPresentation, err := LoadPresentationFromJSON(originalJson)
	require.Nil(t, err)
	require.NotNil(t, loadedPresentation)

	loadedJson, err := loadedPresentation.ToJSON()
	require.Nil(t, err)
	require.NotNil(t, loadedJson)

	require.JSONEq(t, string(originalJson), string(loadedJson))
}

func Test_closePresentation(t *testing.T) {
	processedCredential, err := testCredential.Process(testCredDefReqMeta, testMasterSecret, testCredentialDef, testRevRegDef)
	require.Nil(t, err)

	presentationReq, err := PresentationRequestFromJSON(testPresentationReqJson)
	require.Nil(t, err)

	credRevState, err := NewCredentialRevocationState(testRevRegDef, testRevRegDeltaInit, testCredRevInfo, testTimestamp)
	require.Nil(t, err)

	credentialEntries := []CredentialEntry{{
		credential: processedCredential,
		timestamp:  testTimestamp,
		revState:   credRevState,
	}}

	credentialProves := []CredentialProve{{
		entryIndex:  0,
		referent:    testReferent,
		isPredicate: false,
		reveal:      true,
	}}

	presentation, err := NewPresentation(
		presentationReq,
		credentialEntries,
		credentialProves,
		[]string{},
		[]string{},
		testMasterSecret,
		[]Schema{*testSchema},
		[]CredentialDefinition{*testCredentialDef},
	)

	require.Nil(t, err)
	require.NotNil(t, presentation)

	presentation.close()
	require.True(t, presentation.isClosed)
	presentation.close() // should not panic
}
