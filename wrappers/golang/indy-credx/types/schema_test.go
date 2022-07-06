package types

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	"testing"
)

var (
	testDid           = "55GkHamhTU1ZbTbV2ab9DE"
	testSchemaName    = "name"
	testSchemaVersion = "1"
	testAttrsNames    = []string{"attr"}
	testAttrsValues   = []string{"values"}
	testSeqNo         = int64(15)
)

func Test_NewSchema(t *testing.T) {
	schema, err := NewSchema(
		testDid,
		testSchemaName,
		testSchemaVersion,
		testAttrsNames,
		testSeqNo,
	)

	require.Nil(t, err)
	require.NotNil(t, schema)
}

func Test_JsonSchema(t *testing.T) {
	originalSchema, _ := NewSchema(
		testDid,
		testSchemaName,
		testSchemaVersion,
		testAttrsNames,
		testSeqNo,
	)

	originalJson, err := originalSchema.ToJSON()
	require.Nil(t, err)
	require.NotNil(t, originalJson)

	expectedResponse := json.RawMessage(
		"{\"ver\":\"1.0\",\"id\":\"55GkHamhTU1ZbTbV2ab9DE:2:name:1\",\"name\":\"name\",\"version\":\"1\",\"attrNames\":[\"attr\"],\"seqNo\":15}",
	)

	require.JSONEq(t, string(originalJson), string(expectedResponse))

	loadedSchema, err := LoadSchemaFromJSON(originalJson)
	require.Nil(t, err)
	require.NotNil(t, loadedSchema)

	loadedJson, _ := loadedSchema.ToJSON()

	require.JSONEq(t, string(loadedJson), string(expectedResponse))
}

func Test_GetSchemaID(t *testing.T) {
	schema, _ := NewSchema(
		testDid,
		testSchemaName,
		testSchemaVersion,
		testAttrsNames,
		testSeqNo,
	)
	expectedResponse := "55GkHamhTU1ZbTbV2ab9DE:2:name:1"
	id, err := schema.GetID()

	require.Nil(t, err)
	require.NotNil(t, id)
	require.Equal(t, expectedResponse, id)
}

func Test_closeSchema(t *testing.T) {
	schema, _ := NewSchema(
		testDid,
		testSchemaName,
		testSchemaVersion,
		testAttrsNames,
		testSeqNo,
	)
	schema.close()
	require.True(t, schema.isClosed)
	schema.close() // should not panic
}
