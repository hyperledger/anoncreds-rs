package types

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_NewMasterSecret(t *testing.T) {
	masterSecret, err := NewMasterSecret()

	require.Nil(t, err)
	require.NotNil(t, masterSecret)
}

func Test_JsonMasterSecret(t *testing.T) {
	originalMasterSecret, _ := NewMasterSecret()
	originalJson, err := originalMasterSecret.ToJSON()

	require.Nil(t, err)
	require.NotNil(t, originalJson)

	loadedMasterSecret, err := LoadMasterSecretFromJSON(originalJson)
	require.Nil(t, err)
	require.NotNil(t, loadedMasterSecret)

	loadedJson, err := loadedMasterSecret.ToJSON()
	require.Nil(t, err)
	require.NotNil(t, loadedJson)

	require.Equal(t, originalJson, loadedJson)
}

func Test_closeMasterSecret(t *testing.T) {
	masterSecret, _ := NewMasterSecret()
	masterSecret.close()
	require.True(t, masterSecret.isClosed)
	masterSecret.close() // should not panic
}
