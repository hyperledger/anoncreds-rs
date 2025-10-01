using System.Text.Json;
using AnonCredsNet.Models;
using AnonCredsNet.Requests;
using Xunit;

namespace AnonCredsNet.Tests;

public class NonRevokedIntervalsTests
{
    private const string IssuerId = "mock:uri";
    private const string Schema1Id = "mock:uri:schema1";
    private const string Schema2Id = "mock:uri:schema2";
    private const string CredDef1Id = "mock:uri:1";
    private const string CredDef2Id = "mock:uri:2";
    private const string RevReg1Id = "mock:uri:revregid1";

    [Fact]
    public void Global_Interval_Succeeds_Local_Fails_Without_Override()
    {
        // Setup two schemas and cred defs: one revocable, one not
        var schema1 = Schema.Create(
            "gvt",
            "1.0",
            IssuerId,
            JsonSerializer.Serialize(new[] { "name", "sex", "age", "height" })
        );
        var schema2 = Schema.Create(
            "hogwarts",
            "1.0",
            IssuerId,
            JsonSerializer.Serialize(new[] { "wand", "house", "year" })
        );
        var (cd1, cd1Priv, k1) = CredentialDefinition.Create(
            Schema1Id,
            IssuerId,
            schema1,
            "tag1",
            "CL",
            "{\"support_revocation\": true}"
        );
        var (cd2, cd2Priv, k2) = CredentialDefinition.Create(
            Schema2Id,
            IssuerId,
            schema2,
            "tag2",
            "CL",
            "{\"support_revocation\": false}"
        );

        var (revDef, revPriv) = RevocationRegistryDefinition.Create(
            cd1,
            CredDef1Id,
            IssuerId,
            "tag",
            "CL_ACCUM",
            10,
            null
        );
        var t0 = 8ul; // initial list before issuance
        var revList = RevocationStatusList.Create(
            cd1,
            RevReg1Id,
            revDef,
            revPriv,
            IssuerId,
            true,
            t0
        );

        var ls = LinkSecret.Create();
        var lsId = "default";
        var offer1 = CredentialOffer.Create(Schema1Id, CredDef1Id, k1);
        var offer2 = CredentialOffer.Create(Schema2Id, CredDef2Id, k2);
        var (req1, meta1) = CredentialRequest.Create(cd1, ls, lsId, offer1, "entropy");
        var (req2, meta2) = CredentialRequest.Create(cd2, ls, lsId, offer2, "entropy");

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
            RevRegDef = revDef,
            RevRegDefPrivate = revPriv,
            RevStatusList = revList,
            RevRegIndex = 9u,
        };

        var (cred1, _) = Credential.Create(
            cd1,
            cd1Priv,
            offer1,
            req1,
            values1,
            null,
            null,
            revList,
            revCfg
        );
        var (cred2, _) = Credential.Create(
            cd2,
            cd2Priv,
            offer2,
            req2,
            values2,
            null,
            null,
            null,
            null
        );

        var proc1 = cred1.Process(meta1, ls, cd1, revDef);
        var proc2 = cred2.Process(meta2, ls, cd2, null);

        // Issue revocation at t=9 (within global [5,25])
        var tIssue = 9ul;
        var revListIssued = revList.Update(cd1, revDef, revPriv, new[] { 9ul }, null, tIssue);
        var revState = RevocationState.Create(revDef, revListIssued, 9u, revDef.TailsLocation);

        // Request with global non_revoked window [5,25] and local windows for two referents [10,20]
        var nonce = AnonCreds.GenerateNonce();
        var presReqJson = JsonSerializer.Serialize(
            new
            {
                nonce,
                name = "both_rev_attr",
                version = "0.1",
                requested_attributes = new
                {
                    attr1_referent = new { name = "name", issuer_id = IssuerId },
                    attr2_referent = new { name = "sex", non_revoked = new { from = 10, to = 20 } },
                    attr4_referent = new { names = new[] { "height" } },
                    attr5_referent = new
                    {
                        names = new[] { "wand", "house", "year" },
                        non_revoked = new { from = 10, to = 20 },
                    },
                },
                requested_predicates = new
                {
                    predicate1_referent = new
                    {
                        name = "age",
                        p_type = ">=",
                        p_value = 18,
                    },
                },
                non_revoked = new { from = 5, to = 25 },
            }
        );
        var presReq = PresentationRequest.FromJson(presReqJson);

        // Build credentials array with referent mapping so attr5 (hogwarts) maps to second credential
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
        var credDefsJson = JsonSerializer.Serialize(new[] { cd1.ToJson(), cd2.ToJson() });
        var schemaIdsJson = JsonSerializer.Serialize(new[] { Schema1Id, Schema2Id });
        var credDefIdsJson = JsonSerializer.Serialize(new[] { CredDef1Id, CredDef2Id });
        var revRegsJson = JsonSerializer.Serialize(
            new Dictionary<string, string> { { RevReg1Id, revDef.ToJson() } }
        );
        var revListsJson = JsonSerializer.Serialize(
            new Dictionary<string, string> { { RevReg1Id, revListIssued.ToJson() } }
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

        // Without overrides, local windows [10,20] require rev status at from=10; our proof is at 9 -> expect failure
        var okNoOverride = presentation.Verify(
            presReq,
            schemasJson,
            credDefsJson,
            schemaIdsJson,
            credDefIdsJson,
            revRegsJson,
            revListsJson,
            JsonSerializer.Serialize(new[] { RevReg1Id }),
            null
        );
        Assert.False(okNoOverride);

        // With override mapping requested_from 10 -> use rev list at 9
        var overrideJson = JsonSerializer.Serialize(
            new Dictionary<string, Dictionary<string, int>>
            {
                {
                    RevReg1Id,
                    new Dictionary<string, int> { { "10", 9 } }
                },
            }
        );
        var okWithOverride = presentation.Verify(
            presReq,
            schemasJson,
            credDefsJson,
            schemaIdsJson,
            credDefIdsJson,
            revRegsJson,
            revListsJson,
            JsonSerializer.Serialize(new[] { RevReg1Id }),
            overrideJson
        );
        Assert.True(okWithOverride);
    }
}
