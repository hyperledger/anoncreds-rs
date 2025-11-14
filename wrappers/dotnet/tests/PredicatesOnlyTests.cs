using System.Text.Json;
using AnonCredsNet.Models;
using AnonCredsNet.Requests;
using Xunit;

namespace AnonCredsNet.Tests;

public class PredicatesOnlyTests
{
    private const string IssuerId = "mock:uri";
    private const string SchemaId = "mock:uri:schemaP";
    private const string CredDefId = "mock:uri:cdP";
    private const string RevRegId = "mock:uri:revregP";

    [Fact]
    public void Predicates_Only_Passes_With_Revocation()
    {
        var schema = Schema.Create(
            "gvt",
            "1.0",
            IssuerId,
            JsonSerializer.Serialize(new[] { "name", "sex", "age", "height" })
        );
        var (cd, cdPriv, k) = CredentialDefinition.Create(
            SchemaId,
            IssuerId,
            schema,
            "tag",
            "CL",
            "{\"support_revocation\": true}"
        );
        var (revDef, revPriv) = RevocationRegistryDefinition.Create(
            cd,
            CredDefId,
            IssuerId,
            "tag",
            "CL_ACCUM",
            10,
            null
        );
        var t0 = 10ul;
        var revList = RevocationStatusList.Create(
            cd,
            RevRegId,
            revDef,
            revPriv,
            IssuerId,
            true,
            t0
        );

        var ls = LinkSecret.Create();
        var offer = CredentialOffer.Create(SchemaId, CredDefId, k);
        var (req, meta) = CredentialRequest.Create(cd, ls, "default", offer, "entropy");

        var values = JsonSerializer.Serialize(
            new Dictionary<string, string>
            {
                { "sex", "male" },
                { "name", "Alex" },
                { "height", "175" },
                { "age", "28" },
            }
        );
        var revCfg = new CredentialRevocationConfig
        {
            RevRegDef = revDef,
            RevRegDefPrivate = revPriv,
            RevStatusList = revList,
            RevRegIndex = 1u,
        };
        var (cred, _) = Credential.Create(
            cd,
            cdPriv,
            offer,
            req,
            values,
            null,
            null,
            revList,
            revCfg
        );
        var proc = cred.Process(meta, ls, cd, revDef);

        // timestamp > t0 and inside global window
        var tIssue = t0 + 2; // 12
        var revListIssued = revList.Update(cd, revDef, revPriv, new[] { 1ul }, null, tIssue);
        var revState = RevocationState.Create(revDef, revListIssued, 1u, revDef.TailsLocation);

        var nonce = AnonCreds.GenerateNonce();
        var presReqJson = JsonSerializer.Serialize(
            new
            {
                nonce,
                name = "pred_only",
                version = "0.1",
                requested_attributes = new { },
                requested_predicates = new
                {
                    predicate1_referent = new
                    {
                        name = "age",
                        p_type = ">=",
                        p_value = 18,
                    },
                },
                non_revoked = new { from = 10, to = 200 },
            }
        );
        var presReq = PresentationRequest.FromJson(presReqJson);

        var credsArray = JsonSerializer.Serialize(
            new[]
            {
                new
                {
                    credential = proc.ToJson(),
                    timestamp = (int?)tIssue,
                    rev_state = (string?)revState.ToJson(),
                    referents = new[] { "predicate1_referent" },
                },
            }
        );
        var schemasJson = JsonSerializer.Serialize(new[] { schema.ToJson() });
        var credDefsJson = JsonSerializer.Serialize(new[] { cd.ToJson() });
        var schemaIdsJson = JsonSerializer.Serialize(new[] { SchemaId });
        var credDefIdsJson = JsonSerializer.Serialize(new[] { CredDefId });
        var revRegsJson = JsonSerializer.Serialize(
            new Dictionary<string, string> { { RevRegId, revDef.ToJson() } }
        );
        var revListsJson = JsonSerializer.Serialize(
            new Dictionary<string, string> { { RevRegId, revListIssued.ToJson() } }
        );

        var presentation = Presentation.CreateFromJson(
            presReq,
            credsArray,
            JsonSerializer.Serialize(new Dictionary<string, string>()),
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
            JsonSerializer.Serialize(new[] { RevRegId }),
            null
        );
        Assert.True(ok);
    }

    [Fact]
    public void Predicate_Fails_With_Local_Window_Then_Succeeds_With_Override()
    {
        var schema = Schema.Create(
            "gvt",
            "1.0",
            IssuerId,
            JsonSerializer.Serialize(new[] { "name", "sex", "age", "height" })
        );
        var (cd, cdPriv, k) = CredentialDefinition.Create(
            SchemaId,
            IssuerId,
            schema,
            "tag",
            "CL",
            "{\"support_revocation\": true}"
        );
        var (revDef, revPriv) = RevocationRegistryDefinition.Create(
            cd,
            CredDefId,
            IssuerId,
            "tag",
            "CL_ACCUM",
            10,
            null
        );
        var t0 = 8ul;
        var revList = RevocationStatusList.Create(
            cd,
            RevRegId,
            revDef,
            revPriv,
            IssuerId,
            true,
            t0
        );

        var ls = LinkSecret.Create();
        var offer = CredentialOffer.Create(SchemaId, CredDefId, k);
        var (req, meta) = CredentialRequest.Create(cd, ls, "default", offer, "entropy");

        var values = JsonSerializer.Serialize(
            new Dictionary<string, string>
            {
                { "sex", "male" },
                { "name", "Alex" },
                { "height", "175" },
                { "age", "28" },
            }
        );
        var revCfg = new CredentialRevocationConfig
        {
            RevRegDef = revDef,
            RevRegDefPrivate = revPriv,
            RevStatusList = revList,
            RevRegIndex = 9u,
        };
        var (cred, _) = Credential.Create(
            cd,
            cdPriv,
            offer,
            req,
            values,
            null,
            null,
            revList,
            revCfg
        );
        var proc = cred.Process(meta, ls, cd, revDef);

        // Issue at t=9, local window will require from=10 later
        var tIssue = 9ul;
        var revListIssued = revList.Update(cd, revDef, revPriv, new[] { 9ul }, null, tIssue);
        var revState = RevocationState.Create(revDef, revListIssued, 9u, revDef.TailsLocation);

        var nonce = AnonCreds.GenerateNonce();
        var presReqJson = JsonSerializer.Serialize(
            new
            {
                nonce,
                name = "pred_local_window",
                version = "0.1",
                requested_attributes = new { },
                requested_predicates = new
                {
                    predicate1_referent = new
                    {
                        name = "age",
                        p_type = ">=",
                        p_value = 18,
                        non_revoked = new { from = 10, to = 20 },
                    },
                },
                non_revoked = new { from = 5, to = 25 },
            }
        );
        var presReq = PresentationRequest.FromJson(presReqJson);

        var credsArray = JsonSerializer.Serialize(
            new[]
            {
                new
                {
                    credential = proc.ToJson(),
                    timestamp = (int?)tIssue,
                    rev_state = (string?)revState.ToJson(),
                    referents = new[] { "predicate1_referent" },
                },
            }
        );
        var schemasJson = JsonSerializer.Serialize(new[] { schema.ToJson() });
        var credDefsJson = JsonSerializer.Serialize(new[] { cd.ToJson() });
        var schemaIdsJson = JsonSerializer.Serialize(new[] { SchemaId });
        var credDefIdsJson = JsonSerializer.Serialize(new[] { CredDefId });
        var revRegsJson = JsonSerializer.Serialize(
            new Dictionary<string, string> { { RevRegId, revDef.ToJson() } }
        );
        var revListsJson = JsonSerializer.Serialize(
            new Dictionary<string, string> { { RevRegId, revListIssued.ToJson() } }
        );

        var presentation = Presentation.CreateFromJson(
            presReq,
            credsArray,
            JsonSerializer.Serialize(new Dictionary<string, string>()),
            ls,
            schemasJson,
            credDefsJson,
            schemaIdsJson,
            credDefIdsJson,
            revRegsJson,
            revListsJson
        );

        var okNoOverride = presentation.Verify(
            presReq,
            schemasJson,
            credDefsJson,
            schemaIdsJson,
            credDefIdsJson,
            revRegsJson,
            revListsJson,
            JsonSerializer.Serialize(new[] { RevRegId }),
            null
        );
        Assert.False(okNoOverride);

        var overrideJson = JsonSerializer.Serialize(
            new Dictionary<string, Dictionary<string, int>>
            {
                {
                    RevRegId,
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
            JsonSerializer.Serialize(new[] { RevRegId }),
            overrideJson
        );
        Assert.True(okWithOverride);
    }
}
