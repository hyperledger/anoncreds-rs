using System.Collections.Generic;
using System.Text.Json;
using AnonCredsNet.Models;
using AnonCredsNet.Requests;
using Xunit;

namespace AnonCredsNet.Tests;

public class W3cTests
{
    [Fact]
    public void W3cEndToEnd()
    {
        var issuerId = "mock:uri";
        var schemaId = "mock:uri";
        var credDefId = "mock:uri";
        var revRegId = "mock:uri:revregid";
        var entropy = "entropy";
        uint revIdx = 1;

        var schema = Schema.Create(
            "schema name",
            "1.0.0",
            issuerId,
            JsonSerializer.Serialize(new[] { "name", "age", "sex", "height" })
        );

        var (credDef, credDefPriv, keyProof) = CredentialDefinition.Create(
            schemaId,
            issuerId,
            schema,
            "tag",
            "CL",
            "{\"support_revocation\": true}"
        );

        var (revRegDef, revRegPriv) = RevocationRegistryDefinition.Create(
            credDef,
            credDefId,
            issuerId,
            "some_tag",
            "CL_ACCUM",
            10,
            null
        );

        ulong timeCreateRevStatusList = 12;
        var revocationStatusList = RevocationStatusList.Create(
            credDef,
            revRegId,
            revRegDef,
            revRegPriv,
            issuerId,
            true,
            timeCreateRevStatusList
        );

        var linkSecret = LinkSecret.Create();
        var linkSecretId = "default";
        var credOffer = CredentialOffer.Create(schemaId, credDefId, keyProof);
        var (credReq, credReqMeta) = CredentialRequest.Create(
            credDef,
            linkSecret,
            linkSecretId,
            credOffer,
            entropy
        );

        var credValues = JsonSerializer.Serialize(
            new Dictionary<string, string>
            {
                ["sex"] = "male",
                ["name"] = "Alex",
                ["height"] = "175",
                ["age"] = "28",
            }
        );
        var revConfig = new CredentialRevocationConfig
        {
            RevRegDef = revRegDef,
            RevRegDefPrivate = revRegPriv,
            RevStatusList = revocationStatusList,
            RevRegIndex = revIdx,
        };

        var w3cCred = W3cCredential.Create(
            credDef,
            credDefPriv,
            credOffer,
            credReq,
            credValues,
            revConfig,
            null
        );

        var processedW3c = w3cCred.Process(credReqMeta, linkSecret, credDef, revRegDef);

        // Convert to legacy and back to ensure conversions work
        var legacy = processedW3c.ToLegacy();
        var w3cAgain = W3cCredential.FromLegacy(legacy, issuerId);

        // Prepare verification artifacts
        var timeAfterCreatingCred = timeCreateRevStatusList + 1;
        var issuedRevStatusList = revocationStatusList.Update(
            credDef,
            revRegDef,
            revRegPriv,
            new[] { (ulong)revIdx },
            null,
            timeAfterCreatingCred
        );

        var nonce = AnonCreds.GenerateNonce();
        var presReqObj = new
        {
            nonce,
            name = "pres_req_1",
            version = "0.1",
            requested_attributes = new Dictionary<string, object>
            {
                ["attr1_referent"] = new Dictionary<string, object>
                {
                    ["name"] = "name",
                    ["issuer_id"] = issuerId,
                },
                ["attr2_referent"] = new Dictionary<string, object>
                {
                    ["names"] = new[] { "name", "height" },
                },
            },
            requested_predicates = new Dictionary<string, object>
            {
                ["predicate1_referent"] = new Dictionary<string, object>
                {
                    ["name"] = "age",
                    ["p_type"] = ">=",
                    ["p_value"] = 18,
                },
            },
            non_revoked = new Dictionary<string, int> { ["from"] = 10, ["to"] = 200 },
        };
        var presReqJson = JsonSerializer.Serialize(presReqObj);
        var presReq = PresentationRequest.FromJson(presReqJson);

        // Build revocation state using the issued status list at the matching timestamp
        var revState = RevocationState.Create(
            revRegDef,
            issuedRevStatusList,
            revIdx,
            revRegDef.TailsLocation
        );

        var credentialsJson = JsonSerializer.Serialize(
            new[]
            {
                new
                {
                    credential = processedW3c.ToJson(),
                    timestamp = timeAfterCreatingCred,
                    rev_state = revState.ToJson(),
                },
            }
        );
        var schemasJson = JsonSerializer.Serialize(
            new Dictionary<string, string> { [schemaId] = schema.ToJson() }
        );
        var credDefsJson = JsonSerializer.Serialize(
            new Dictionary<string, string> { [credDefId] = credDef.ToJson() }
        );

        var presentation = W3cPresentation.CreateFromJson(
            presReq,
            credentialsJson,
            linkSecret,
            schemasJson,
            credDefsJson,
            JsonSerializer.Serialize(new[] { schemaId }),
            JsonSerializer.Serialize(new[] { credDefId }),
            null
        );

        var revRegDefsJson = JsonSerializer.Serialize(
            new Dictionary<string, string> { [revRegId] = revRegDef.ToJson() }
        );
        var revRegDefIdsJson = JsonSerializer.Serialize(new[] { revRegId });

        var isValid = presentation.Verify(
            presReq,
            schemasJson,
            credDefsJson,
            JsonSerializer.Serialize(new[] { schemaId }),
            JsonSerializer.Serialize(new[] { credDefId }),
            revRegDefsJson,
            JsonSerializer.Serialize(new[] { issuedRevStatusList.ToJson() }),
            revRegDefIdsJson,
            null
        );

        Assert.True(isValid);

        // Revoke and verify should fail
        var timeRevoke = timeAfterCreatingCred + 1;
        var revokedStatusList = issuedRevStatusList.Update(
            credDef,
            revRegDef,
            revRegPriv,
            null,
            new[] { (ulong)revIdx },
            timeRevoke
        );

        var isValidAfterRevoke = presentation.Verify(
            presReq,
            schemasJson,
            credDefsJson,
            JsonSerializer.Serialize(new[] { schemaId }),
            JsonSerializer.Serialize(new[] { credDefId }),
            revRegDefsJson,
            JsonSerializer.Serialize(new[] { revokedStatusList.ToJson() }),
            revRegDefIdsJson,
            null
        );
        Assert.False(isValidAfterRevoke);
    }

    [Fact]
    public void W3cNonRevocableCredential_Verifies()
    {
        var issuerId = "mock:uri";
        var schemaId = "mock:uri";
        var credDefId = "mock:uri";
        var entropy = "entropy";

        var schema = Schema.Create(
            "schema name",
            "1.0.0",
            issuerId,
            JsonSerializer.Serialize(new[] { "name", "age" })
        );

        var (credDef, credDefPriv, keyProof) = CredentialDefinition.Create(
            schemaId,
            issuerId,
            schema,
            "tag",
            "CL",
            "{\"support_revocation\": false}"
        );

        var linkSecret = LinkSecret.Create();
        var linkSecretId = "default";
        var offer = CredentialOffer.Create(schemaId, credDefId, keyProof);
        var (req, reqMeta) = CredentialRequest.Create(
            credDef,
            linkSecret,
            linkSecretId,
            offer,
            entropy
        );

        var values = JsonSerializer.Serialize(
            new Dictionary<string, string> { ["name"] = "Alex", ["age"] = "28" }
        );

        var w3cCred = W3cCredential.Create(credDef, credDefPriv, offer, req, values, null, null);
        var processed = w3cCred.Process(reqMeta, linkSecret, credDef, null);

        var nonce = AnonCreds.GenerateNonce();
        var presReqObj = new
        {
            nonce,
            name = "pres_req_1",
            version = "0.1",
            requested_attributes = new Dictionary<string, object>
            {
                ["attr1_referent"] = new Dictionary<string, object> { ["name"] = "name" },
            },
            requested_predicates = new Dictionary<string, object>
            {
                ["predicate1_referent"] = new Dictionary<string, object>
                {
                    ["name"] = "age",
                    ["p_type"] = ">=",
                    ["p_value"] = 18,
                },
            },
        };
        var presReq = PresentationRequest.FromJson(JsonSerializer.Serialize(presReqObj));

        var credentialsJson = JsonSerializer.Serialize(
            new[] { new { credential = processed.ToJson() } }
        );
        var schemasJson = JsonSerializer.Serialize(
            new Dictionary<string, string> { [schemaId] = schema.ToJson() }
        );
        var credDefsJson = JsonSerializer.Serialize(
            new Dictionary<string, string> { [credDefId] = credDef.ToJson() }
        );

        var presentation = W3cPresentation.CreateFromJson(
            presReq,
            credentialsJson,
            linkSecret,
            schemasJson,
            credDefsJson,
            JsonSerializer.Serialize(new[] { schemaId }),
            JsonSerializer.Serialize(new[] { credDefId }),
            null
        );

        var isValid = presentation.Verify(
            presReq,
            schemasJson,
            credDefsJson,
            JsonSerializer.Serialize(new[] { schemaId }),
            JsonSerializer.Serialize(new[] { credDefId }),
            null,
            null,
            null,
            null
        );

        Assert.True(isValid);
    }

    [Fact]
    public void W3c_Verify_WithIntervalOverride()
    {
        var issuerId = "mock:uri";
        var schemaId = "mock:uri";
        var credDefId = "mock:uri";
        var revRegId = "mock:uri:revregid";
        var entropy = "entropy";
        uint revIdx = 3;

        var schema = Schema.Create(
            "schema name",
            "1.0.0",
            issuerId,
            JsonSerializer.Serialize(new[] { "name" })
        );

        var (credDef, credDefPriv, keyProof) = CredentialDefinition.Create(
            schemaId,
            issuerId,
            schema,
            "tag",
            "CL",
            "{\"support_revocation\": true}"
        );

        var (revRegDef, revRegPriv) = RevocationRegistryDefinition.Create(
            credDef,
            credDefId,
            issuerId,
            "some_tag",
            "CL_ACCUM",
            10,
            null
        );

        ulong t0 = 100;
        var status0 = RevocationStatusList.Create(
            credDef,
            revRegId,
            revRegDef,
            revRegPriv,
            issuerId,
            true,
            t0
        );

        var linkSecret = LinkSecret.Create();
        var offer = CredentialOffer.Create(schemaId, credDefId, keyProof);
        var (req, reqMeta) = CredentialRequest.Create(
            credDef,
            linkSecret,
            "default",
            offer,
            entropy
        );

        var values = JsonSerializer.Serialize(new Dictionary<string, string> { ["name"] = "Al" });
        var revConfig = new CredentialRevocationConfig
        {
            RevRegDef = revRegDef,
            RevRegDefPrivate = revRegPriv,
            RevStatusList = status0,
            RevRegIndex = revIdx,
        };

        var w3cCred = W3cCredential.Create(
            credDef,
            credDefPriv,
            offer,
            req,
            values,
            revConfig,
            null
        );
        var processed = w3cCred.Process(reqMeta, linkSecret, credDef, revRegDef);

        var t1 = t0 + 1;
        var status1 = status0.Update(
            credDef,
            revRegDef,
            revRegPriv,
            new[] { (ulong)revIdx },
            null,
            t1
        );

        var revState = RevocationState.Create(revRegDef, status1, revIdx, revRegDef.TailsLocation);

        var credentialsJson = JsonSerializer.Serialize(
            new[]
            {
                new
                {
                    credential = processed.ToJson(),
                    timestamp = t1,
                    rev_state = revState.ToJson(),
                },
            }
        );

        var schemasJson = JsonSerializer.Serialize(
            new Dictionary<string, string> { [schemaId] = schema.ToJson() }
        );
        var credDefsJson = JsonSerializer.Serialize(
            new Dictionary<string, string> { [credDefId] = credDef.ToJson() }
        );

        var nonce = AnonCreds.GenerateNonce();
        var presReqObj = new
        {
            nonce,
            name = "pr",
            version = "0.1",
            requested_attributes = new Dictionary<string, object>
            {
                ["a1"] = new Dictionary<string, object> { ["name"] = "name" },
            },
            non_revoked = new Dictionary<string, int>
            {
                ["from"] = (int)t0,
                ["to"] = (int)(t1 + 10),
            },
        };
        var presReq = PresentationRequest.FromJson(JsonSerializer.Serialize(presReqObj));

        var presentation = W3cPresentation.CreateFromJson(
            presReq,
            credentialsJson,
            linkSecret,
            schemasJson,
            credDefsJson,
            JsonSerializer.Serialize(new[] { schemaId }),
            JsonSerializer.Serialize(new[] { credDefId }),
            null
        );

        var overrides = JsonSerializer.Serialize(
            new Dictionary<string, Dictionary<string, int>>
            {
                [revRegId] = new Dictionary<string, int> { [t0.ToString()] = (int)t1 },
            }
        );

        var isValid = presentation.Verify(
            presReq,
            schemasJson,
            credDefsJson,
            JsonSerializer.Serialize(new[] { schemaId }),
            JsonSerializer.Serialize(new[] { credDefId }),
            JsonSerializer.Serialize(
                new Dictionary<string, string> { [revRegId] = revRegDef.ToJson() }
            ),
            JsonSerializer.Serialize(new[] { status1.ToJson() }),
            JsonSerializer.Serialize(new[] { revRegId }),
            overrides
        );

        Assert.True(isValid);
    }
}
