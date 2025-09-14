using System.Text.Json;
using AnonCredsNet.Models;
using AnonCredsNet.Requests;
using Xunit;

namespace AnonCredsNet.Tests;

public class AnonCredsNetTests
{
    // Removed client facade; using model-centric APIs

    [Fact]
    public void TestFullFlow()
    {
        // Ported from wrappers/python/demo/test.py

        // 1. Setup variables
        var issuerId = "mock:uri";
        var schemaId = "mock:uri";
        var credDefId = "mock:uri";
        var revRegId = "mock:uri:revregid";
        var entropy = "entropy";
        var revIdx = 1u;

        // 2. Create Schema
        var attrNames = new[] { "name", "age", "sex", "height" };
        var schema = Schema.Create(
            "schema name",
            "1.0.0",
            issuerId,
            JsonSerializer.Serialize(attrNames)
        );

        // 3. Create Credential Definition
        var (credDef, credDefPrivate, keyProof) = CredentialDefinition.Create(
            schemaId,
            issuerId,
            schema,
            "tag",
            "CL",
            "{\"support_revocation\": true}"
        );

        // 4. Create Revocation Registry Definition
        var timeCreateRevStatusList = 12ul;
        var (revRegDef, revRegDefPrivate) = RevocationRegistryDefinition.Create(
            credDef,
            credDefId,
            issuerId,
            "some_tag",
            "CL_ACCUM",
            10,
            null
        );
        // Create initial Revocation Status List at the given timestamp
        var revocationStatusList = RevocationStatusList.Create(
            credDef,
            revRegId,
            revRegDef,
            revRegDefPrivate,
            issuerId,
            true,
            timeCreateRevStatusList
        );

        // 6. Create Link Secret
        var linkSecret = LinkSecret.Create();
        var linkSecretId = "default";

        // 7. Create Credential Offer
        var credOffer = CredentialOffer.Create(schemaId, credDefId, keyProof);

        // 8. Create Credential Request
        var (credRequest, credRequestMetadata) = CredentialRequest.Create(
            credDef,
            linkSecret,
            linkSecretId,
            credOffer,
            entropy
        );

        // 9. Issue Credential
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
            RevRegDefPrivate = revRegDefPrivate,
            RevStatusList = revocationStatusList,
            RevRegIndex = revIdx,
        };

        var (credential, _) = Credential.Create(
            credDef,
            credDefPrivate,
            credOffer,
            credRequest,
            credValues,
            null,
            null,
            revocationStatusList,
            revConfig
        );

        // 10. Process Credential
        var processedCredential = credential.Process(
            credRequestMetadata,
            linkSecret,
            credDef,
            revRegDef
        );

        // 11. Update Revocation Status List
        var timeAfterCreatingCred = timeCreateRevStatusList + 1;
        var issuedRevStatusList = revocationStatusList.Update(
            credDef,
            revRegDef,
            revRegDefPrivate,
            new[] { (ulong)revIdx },
            null,
            timeAfterCreatingCred
        );

        // 12. Create Presentation Request
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
        var presReq = PresentationRequest.FromJson(presReqJson);

        // 13. Create Revocation State using the issued (updated) status list at timeAfterCreatingCred
        var revState = RevocationState.Create(
            revRegDef,
            issuedRevStatusList,
            revIdx,
            revRegDef.TailsLocation
        );

        // 14. Build Presentation
        var credentialsJson = JsonSerializer.Serialize(
            new[]
            {
                new
                {
                    credential = processedCredential.ToJson(),
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

        // 15. Verify Presentation
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
    }
}
