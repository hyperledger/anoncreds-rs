using System.Text.Json;
using AnonCredsNet.Models;
using AnonCredsNet.Requests;
using Xunit;

namespace AnonCredsNet.Tests;

public class MultipleCredentialsTests
{
    [Fact]
    public void Multiple_Credentials_Global_NonRevoked_Succeeds()
    {
        // Based on tests/multiple-credentials.rs happy path for classic
        var issuerId = "mock:uri";
        var schema1Id = "mock:uri:schema1";
        var schema2Id = "mock:uri:schema2";
        var credDef1Id = "mock:uri:1";
        var credDef2Id = "mock:uri:2";
        var revReg1Id = "mock:uri:revregid1";
        var entropy = "entropy";

        // Create two schemas
        var schema1 = Schema.Create(
            "gvt",
            "1.0",
            issuerId,
            JsonSerializer.Serialize(new[] { "name", "sex", "age", "height" })
        );
        var schema2 = Schema.Create(
            "hogwarts",
            "1.0",
            issuerId,
            JsonSerializer.Serialize(new[] { "wand", "house", "year" })
        );

        // cred def 1 supports revocation, cred def 2 does not
        var (credDef1, credDef1Priv, k1) = CredentialDefinition.Create(
            schema1Id,
            issuerId,
            schema1,
            "tag1",
            "CL",
            "{\"support_revocation\": true}"
        );
        var (credDef2, credDef2Priv, k2) = CredentialDefinition.Create(
            schema2Id,
            issuerId,
            schema2,
            "tag2",
            "CL",
            "{\"support_revocation\": false}"
        );

        // Revocation registry for credDef1
        var (revRegDef1, revRegPriv1) = RevocationRegistryDefinition.Create(
            credDef1,
            credDef1Id,
            issuerId,
            "tag",
            "CL_ACCUM",
            10,
            null
        );
        var t0 = 8ul;
        var revList = RevocationStatusList.Create(
            credDef1,
            revReg1Id,
            revRegDef1,
            revRegPriv1,
            issuerId,
            true,
            t0
        );

        // Link secret
        var ls = LinkSecret.Create();
        var lsId = "default";

        // Offers and requests
        var offer1 = CredentialOffer.Create(schema1Id, credDef1Id, k1);
        var offer2 = CredentialOffer.Create(schema2Id, credDef2Id, k2);
        var (req1, meta1) = CredentialRequest.Create(credDef1, ls, lsId, offer1, entropy);
        var (req2, meta2) = CredentialRequest.Create(credDef2, ls, lsId, offer2, entropy);

        // Issue creds
        var values1 = JsonSerializer.Serialize(
            new Dictionary<string, string>
            {
                { "sex", "male" },
                { "name", "Alex" },
                { "height", "175" },
                { "age", "28" },
            }
        );
        var values2 = JsonSerializer.Serialize(
            new Dictionary<string, string>
            {
                { "wand", "dragon-heart-string" },
                { "house", "Hufflepuff" },
                { "year", "1990" },
            }
        );
        var revCfg = new CredentialRevocationConfig
        {
            RevRegDef = revRegDef1,
            RevRegDefPrivate = revRegPriv1,
            RevStatusList = revList,
            RevRegIndex = 9u,
        };

        var (cred1, _) = Credential.Create(
            credDef1,
            credDef1Priv,
            offer1,
            req1,
            values1,
            null,
            null,
            revList,
            revCfg
        );
        var (cred2, _) = Credential.Create(
            credDef2,
            credDef2Priv,
            offer2,
            req2,
            values2,
            null,
            null,
            null,
            null
        );

        // Process
        var proc1 = cred1.Process(meta1, ls, credDef1, revRegDef1);
        var proc2 = cred2.Process(meta2, ls, credDef2, null);

        // Update rev list to issue index 9 at t=9
        var tIssue = 9ul; // within global interval below
        var revListIssued = revList.Update(
            credDef1,
            revRegDef1,
            revRegPriv1,
            new[] { 9ul },
            null,
            tIssue
        );
        var revState = RevocationState.Create(
            revRegDef1,
            revListIssued,
            9u,
            revRegDef1.TailsLocation
        );

        // Request with global non_revoked window [5,25]
        var nonce = AnonCreds.GenerateNonce();
        var presReqJson = $$"""
            {
              "nonce":"{{nonce}}",
              "name":"global_rev",
              "version":"0.1",
              "requested_attributes":{
                "attr1_referent": {"name":"name","issuer_id":"{{issuerId}}"},
                "attr2_referent": {"name":"sex"},
                "attr4_referent": {"names":["height"]},
                "attr5_referent": {"names":["wand","house","year"]}
              },
              "requested_predicates":{
                "predicate1_referent": {"name":"age","p_type":">=","p_value":18}
              },
              "non_revoked": {"from":5, "to":25}
            }
            """;
        presReqJson = presReqJson.Replace("{{nonce}}", nonce).Replace("{{issuerId}}", issuerId);
        var presReq = PresentationRequest.FromJson(presReqJson);

        // Build present credentials (two credentials, attach rev state to the revocable one)
        var credsArray = JsonSerializer.Serialize(
            new[]
            {
                new
                {
                    credential = proc1.ToJson(),
                    timestamp = (int?)tIssue,
                    rev_state = (string?)revState.ToJson(),
                    referents = new[]
                    {
                        "attr1_referent",
                        "attr2_referent",
                        "attr4_referent",
                        "predicate1_referent",
                    },
                },
                new
                {
                    credential = proc2.ToJson(),
                    timestamp = (int?)null,
                    rev_state = (string?)null,
                    referents = new[] { "attr5_referent" },
                },
            }
        );

        var selfAtt = JsonSerializer.Serialize(new Dictionary<string, string>());
        var schemasJson = JsonSerializer.Serialize(new[] { schema1.ToJson(), schema2.ToJson() });
        var credDefsJson = JsonSerializer.Serialize(new[] { credDef1.ToJson(), credDef2.ToJson() });
        var schemaIdsJson = JsonSerializer.Serialize(new[] { schema1Id, schema2Id });
        var credDefIdsJson = JsonSerializer.Serialize(new[] { credDef1Id, credDef2Id });
        var revRegsJson = JsonSerializer.Serialize(
            new Dictionary<string, string> { { revReg1Id, revRegDef1.ToJson() } }
        );
        var revListsJson = JsonSerializer.Serialize(
            new Dictionary<string, string> { { revReg1Id, revListIssued.ToJson() } }
        );

        var presentation = Presentation.CreateFromJson(
            presReq,
            credsArray,
            selfAtt,
            ls,
            schemasJson,
            credDefsJson,
            schemaIdsJson,
            credDefIdsJson,
            revRegsJson,
            revListsJson
        );

        var ok = presentation.Verify(
            presReq,
            schemasJson,
            credDefsJson,
            schemaIdsJson,
            credDefIdsJson,
            revRegsJson,
            revListsJson,
            JsonSerializer.Serialize(new[] { revReg1Id }),
            null
        );

        Assert.True(ok);
    }
}
