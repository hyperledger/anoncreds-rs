using System.Text.Json;
using AnonCredsNet.Models;
using AnonCredsNet.Requests;
using Xunit;

namespace AnonCredsNet.Tests;

public class MultiOverrideRevocationTests
{
    private const string IssuerId = "mock:uri";
    private const string Schema1Id = "mock:uri:schemaMO1";
    private const string Schema2Id = "mock:uri:schemaMO2";
    private const string CredDef1Id = "mock:uri:cdMO1";
    private const string CredDef2Id = "mock:uri:cdMO2";
    private const string RevReg1Id = "mock:uri:revregMO1";
    private const string RevReg2Id = "mock:uri:revregMO2";

    [Fact]
    public void Two_Creds_Different_Local_Windows_Need_Two_Overrides()
    {
        // Create two revocable creds in different registries
        var s1 = Schema.Create(
            "gvt",
            "1.0",
            IssuerId,
            JsonSerializer.Serialize(new[] { "name", "sex", "age", "height" })
        );
        var s2 = Schema.Create(
            "pets",
            "1.0",
            IssuerId,
            JsonSerializer.Serialize(new[] { "animal", "species" })
        );
        var (cd1, cd1Priv, k1) = CredentialDefinition.Create(
            Schema1Id,
            IssuerId,
            s1,
            "tag1",
            "CL",
            "{\"support_revocation\": true}"
        );
        var (cd2, cd2Priv, k2) = CredentialDefinition.Create(
            Schema2Id,
            IssuerId,
            s2,
            "tag2",
            "CL",
            "{\"support_revocation\": true}"
        );
        var (rev1, rev1Priv) = RevocationRegistryDefinition.Create(
            cd1,
            CredDef1Id,
            IssuerId,
            "tag1",
            "CL_ACCUM",
            10,
            null
        );
        var (rev2, rev2Priv) = RevocationRegistryDefinition.Create(
            cd2,
            CredDef2Id,
            IssuerId,
            "tag2",
            "CL_ACCUM",
            10,
            null
        );
        var t0 = 8ul;
        var list1 = RevocationStatusList.Create(cd1, RevReg1Id, rev1, rev1Priv, IssuerId, true, t0);
        var list2 = RevocationStatusList.Create(cd2, RevReg2Id, rev2, rev2Priv, IssuerId, true, t0);

        var ls = LinkSecret.Create();
        // IMPORTANT: Offer must be reused between request and issuance; don't recreate
        var offer1 = CredentialOffer.Create(Schema1Id, CredDef1Id, k1);
        var offer2 = CredentialOffer.Create(Schema2Id, CredDef2Id, k2);
        var (req1, meta1) = CredentialRequest.Create(cd1, ls, "default", offer1, "entropy");
        var (req2, meta2) = CredentialRequest.Create(cd2, ls, "default", offer2, "entropy");

        var vals1 = JsonSerializer.Serialize(
            new Dictionary<string, string>
            {
                { "sex", "male" },
                { "name", "Alex" },
                { "height", "175" },
                { "age", "28" },
            }
        );
        var vals2 = JsonSerializer.Serialize(
            new Dictionary<string, string> { { "animal", "cat" }, { "species", "tabby" } }
        );

        var (cred1, _) = Credential.Create(
            cd1,
            cd1Priv,
            offer1,
            req1,
            vals1,
            null,
            null,
            list1,
            new CredentialRevocationConfig
            {
                RevRegDef = rev1,
                RevRegDefPrivate = rev1Priv,
                RevStatusList = list1,
                RevRegIndex = 9u,
            }
        );
        var (cred2, _) = Credential.Create(
            cd2,
            cd2Priv,
            offer2,
            req2,
            vals2,
            null,
            null,
            list2,
            new CredentialRevocationConfig
            {
                RevRegDef = rev2,
                RevRegDefPrivate = rev2Priv,
                RevStatusList = list2,
                RevRegIndex = 7u,
            }
        );

        var p1 = cred1.Process(meta1, ls, cd1, rev1);
        var p2 = cred2.Process(meta2, ls, cd2, rev2);

        // Issue at t=9 for first, t=11 for second
        var list1Issued = list1.Update(cd1, rev1, rev1Priv, new[] { 9ul }, null, 9ul);
        var list2Issued = list2.Update(cd2, rev2, rev2Priv, new[] { 7ul }, null, 11ul);
        var rs1 = RevocationState.Create(rev1, list1Issued, 9u, rev1.TailsLocation);
        var rs2 = RevocationState.Create(rev2, list2Issued, 7u, rev2.TailsLocation);

        // Request: local windows require from=10 for referents bound to cred1, and from=12 for referents bound to cred2
        var nonce = AnonCreds.GenerateNonce();
        var presReqJson = JsonSerializer.Serialize(
            new
            {
                nonce,
                name = "multi_override",
                version = "0.1",
                requested_attributes = new
                {
                    attr1_referent = new
                    {
                        name = "name",
                        issuer_id = IssuerId,
                        non_revoked = new { from = 10, to = 20 },
                    },
                    attrX_referent = new
                    {
                        names = new[] { "animal", "species" },
                        non_revoked = new { from = 12, to = 20 },
                    },
                },
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
                    credential = p1.ToJson(),
                    timestamp = (int?)9,
                    rev_state = (string?)rs1.ToJson(),
                    referents = new[] { "attr1_referent", "predicate1_referent" },
                },
                new
                {
                    credential = p2.ToJson(),
                    timestamp = (int?)11,
                    rev_state = (string?)rs2.ToJson(),
                    referents = new[] { "attrX_referent" },
                },
            }
        );

        var schemasJson = JsonSerializer.Serialize(new[] { s1.ToJson(), s2.ToJson() });
        var credDefsJson = JsonSerializer.Serialize(new[] { cd1.ToJson(), cd2.ToJson() });
        var schemaIdsJson = JsonSerializer.Serialize(new[] { Schema1Id, Schema2Id });
        var credDefIdsJson = JsonSerializer.Serialize(new[] { CredDef1Id, CredDef2Id });
        var revRegsJson = JsonSerializer.Serialize(
            new Dictionary<string, string>
            {
                { RevReg1Id, rev1.ToJson() },
                { RevReg2Id, rev2.ToJson() },
            }
        );
        var revListsJson = JsonSerializer.Serialize(
            new Dictionary<string, string>
            {
                { RevReg1Id, list1Issued.ToJson() },
                { RevReg2Id, list2Issued.ToJson() },
            }
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

        // Without overrides, should fail
        var okNoOverride = presentation.Verify(
            presReq,
            schemasJson,
            credDefsJson,
            schemaIdsJson,
            credDefIdsJson,
            revRegsJson,
            revListsJson,
            JsonSerializer.Serialize(new[] { RevReg1Id, RevReg2Id }),
            null
        );
        Assert.False(okNoOverride);

        // With overrides for 10->9 and 12->11
        var overrideJson = JsonSerializer.Serialize(
            new Dictionary<string, Dictionary<string, int>>
            {
                {
                    RevReg1Id,
                    new Dictionary<string, int> { { "10", 9 } }
                },
                {
                    RevReg2Id,
                    new Dictionary<string, int> { { "12", 11 } }
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
            JsonSerializer.Serialize(new[] { RevReg1Id, RevReg2Id }),
            overrideJson
        );
        Assert.True(okWithOverride);
    }
}
