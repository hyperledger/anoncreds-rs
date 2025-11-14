using System.Text.Json;
using AnonCredsNet.Models;
using AnonCredsNet.Requests;
using Xunit;

namespace AnonCredsNet.Tests;

public class NonRevocableIntervalsTests
{
    private const string IssuerId = "mock:uri";
    private const string SchemaId = "mock:uri:schemaNR";
    private const string CredDefId = "mock:uri:cdNR";

    [Fact]
    public void NonRevocable_Cred_Ignores_NonRevoked_Windows()
    {
        var schema = Schema.Create(
            "hogwarts",
            "1.0",
            IssuerId,
            JsonSerializer.Serialize(new[] { "wand", "house", "year" })
        );
        var (cd, cdPriv, k) = CredentialDefinition.Create(
            SchemaId,
            IssuerId,
            schema,
            "tag",
            "CL",
            "{\"support_revocation\": false}"
        );

        var ls = LinkSecret.Create();
        var offer = CredentialOffer.Create(SchemaId, CredDefId, k);
        var (req, meta) = CredentialRequest.Create(cd, ls, "default", offer, "entropy");

        var values = JsonSerializer.Serialize(
            new Dictionary<string, string>
            {
                { "wand", "phoenix" },
                { "house", "Gryffindor" },
                { "year", "1997" },
            }
        );
        var (cred, _) = Credential.Create(cd, cdPriv, offer, req, values, null, null, null, null);
        var proc = cred.Process(meta, ls, cd, null);

        var nonce = AnonCreds.GenerateNonce();
        var presReqJson = JsonSerializer.Serialize(
            new
            {
                nonce,
                name = "nr_test",
                version = "0.1",
                requested_attributes = new
                {
                    attr5_referent = new
                    {
                        names = new[] { "wand", "house", "year" },
                        non_revoked = new { from = 10, to = 20 },
                    },
                },
                requested_predicates = new { },
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
                    timestamp = (int?)null,
                    rev_state = (string?)null,
                    referents = new[] { "attr5_referent" },
                },
            }
        );
        var schemasJson = JsonSerializer.Serialize(new[] { schema.ToJson() });
        var credDefsJson = JsonSerializer.Serialize(new[] { cd.ToJson() });
        var schemaIdsJson = JsonSerializer.Serialize(new[] { SchemaId });
        var credDefIdsJson = JsonSerializer.Serialize(new[] { CredDefId });

        var presentation = Presentation.CreateFromJson(
            presReq,
            credsArray,
            JsonSerializer.Serialize(new Dictionary<string, string>()),
            ls,
            schemasJson,
            credDefsJson,
            schemaIdsJson,
            credDefIdsJson,
            null,
            null
        );

        var ok = presentation.Verify(
            presReq,
            schemasJson,
            credDefsJson,
            schemaIdsJson,
            credDefIdsJson,
            null,
            null,
            null,
            null
        );
        Assert.True(ok);
    }
}
