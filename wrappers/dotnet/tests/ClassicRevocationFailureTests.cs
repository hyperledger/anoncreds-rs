using System.Text.Json;
using AnonCredsNet.Models;
using AnonCredsNet.Requests;
using Xunit;

namespace AnonCredsNet.Tests;

public class ClassicRevocationFailureTests
{
    [Fact]
    public void Revocation_Fails_After_Revoke()
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

        var (credential, _) = Credential.Create(
            credDef,
            credDefPriv,
            credOffer,
            credReq,
            credValues,
            null,
            null,
            revocationStatusList,
            revConfig
        );

        var processed = credential.Process(credReqMeta, linkSecret, credDef, revRegDef);

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
        var presReqJson = $$"""
            {
                "nonce": "{{nonce}}",
                "name": "pres_req_1",
                "version": "0.1",
                "requested_attributes": {
                    "attr1_referent": {"name": "name", "issuer_id": "{{issuerId}}"},
                    "attr2_referent": {"name": "sex"},
                    "attr3_referent": {"name": "phone"},
                    "attr4_referent": {"names": ["name", "height"]}
                },
                "requested_predicates": {
                    "predicate1_referent": {"name": "age", "p_type": ">=", "p_value": 18}
                },
                "non_revoked": {"from": 10, "to": 200}
            }
            """;
        presReqJson = presReqJson.Replace("{{nonce}}", nonce).Replace("{{issuerId}}", issuerId);
        var presReq = PresentationRequest.FromJson(presReqJson);

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
                    credential = processed.ToJson(),
                    timestamp = timeAfterCreatingCred,
                    rev_state = revState.ToJson(),
                },
            }
        );

        var selfAttestedJson = JsonSerializer.Serialize(
            new Dictionary<string, string> { ["attr3_referent"] = "8-800-300" }
        );

        var schemasJson = JsonSerializer.Serialize(
            new Dictionary<string, string> { [schemaId] = schema.ToJson() }
        );
        var credDefsJson = JsonSerializer.Serialize(
            new Dictionary<string, string> { [credDefId] = credDef.ToJson() }
        );
        var revRegsJson = JsonSerializer.Serialize(
            new Dictionary<string, string> { [revRegId] = revRegDef.ToJson() }
        );
        var revListsJson = JsonSerializer.Serialize(
            new Dictionary<string, string> { [revRegId] = issuedRevStatusList.ToJson() }
        );

        var presentation = Presentation.CreateFromJson(
            presReq,
            credentialsJson,
            selfAttestedJson,
            linkSecret,
            schemasJson,
            credDefsJson,
            JsonSerializer.Serialize(new[] { schemaId }),
            JsonSerializer.Serialize(new[] { credDefId }),
            revRegsJson,
            revListsJson
        );

        var isValid = presentation.Verify(
            presReq,
            schemasJson,
            credDefsJson,
            JsonSerializer.Serialize(new[] { schemaId }),
            JsonSerializer.Serialize(new[] { credDefId }),
            revRegsJson,
            revListsJson,
            JsonSerializer.Serialize(new[] { revRegId }),
            null
        );
        Assert.True(isValid);

        // Revoke and expect failure
        var timeRevoke = timeAfterCreatingCred + 1;
        var revokedStatusList = issuedRevStatusList.Update(
            credDef,
            revRegDef,
            revRegPriv,
            null,
            new[] { (ulong)revIdx },
            timeRevoke
        );

        var revListsJson2 = JsonSerializer.Serialize(
            new Dictionary<string, string> { [revRegId] = revokedStatusList.ToJson() }
        );

        // Build a new revocation state at the revoke timestamp and create a new presentation
        // so the proof is anchored at a time when the credential is revoked.
        var revokedRevState = RevocationState.Create(
            revRegDef,
            revokedStatusList,
            revIdx,
            revRegDef.TailsLocation
        );

        var credentialsJson2 = JsonSerializer.Serialize(
            new[]
            {
                new
                {
                    credential = processed.ToJson(),
                    timestamp = timeRevoke,
                    rev_state = revokedRevState.ToJson(),
                },
            }
        );

        var presentation2 = Presentation.CreateFromJson(
            presReq,
            credentialsJson2,
            selfAttestedJson,
            linkSecret,
            schemasJson,
            credDefsJson,
            JsonSerializer.Serialize(new[] { schemaId }),
            JsonSerializer.Serialize(new[] { credDefId }),
            revRegsJson,
            revListsJson2
        );

        var isValidAfterRevoke = presentation2.Verify(
            presReq,
            schemasJson,
            credDefsJson,
            JsonSerializer.Serialize(new[] { schemaId }),
            JsonSerializer.Serialize(new[] { credDefId }),
            revRegsJson,
            revListsJson2,
            JsonSerializer.Serialize(new[] { revRegId }),
            null
        );
        Assert.False(isValidAfterRevoke);
    }
}
