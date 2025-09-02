// AnonCreds.cs
using AnonCredsNet.Helpers;
using AnonCredsNet.Objects;
using AnonCredsNet.Requests;

namespace AnonCredsNet;

public class AnonCredsClient
{
    public AnonCredsClient()
    {
        // Placeholder for initialization if needed
    }

    public Presentation CreatePresentation(
        PresentationRequest presReq,
        string credentialsJson,
        string? selfAttestJson,
        LinkSecret linkSecret,
        string schemasJson,
        string credDefsJson
    )
    {
        if (
            presReq == null
            || string.IsNullOrEmpty(credentialsJson)
            || linkSecret == null
            || string.IsNullOrEmpty(schemasJson)
            || string.IsNullOrEmpty(credDefsJson)
        )
            throw new ArgumentNullException("Required parameters cannot be null or empty");
        if (
            credentialsJson.Length > 100000
            || schemasJson.Length > 100000
            || credDefsJson.Length > 100000
        )
            throw new ArgumentException("JSON input too large");
        string presReqJson = presReq.ToJson();
        return Presentation.Create(
            presReqJson,
            credentialsJson,
            selfAttestJson,
            linkSecret,
            schemasJson,
            credDefsJson
        );
    }

    public bool VerifyPresentation(
        Presentation presentation,
        PresentationRequest presReq,
        string schemasJson,
        string credDefsJson,
        string? revRegDefsJson,
        string? revStatusListsJson,
        string? nonRevocJson
    )
    {
        if (
            presentation == null
            || presReq == null
            || string.IsNullOrEmpty(schemasJson)
            || string.IsNullOrEmpty(credDefsJson)
        )
            throw new ArgumentNullException("Required parameters cannot be null or empty");
        if (schemasJson.Length > 100000 || credDefsJson.Length > 100000)
            throw new ArgumentException("JSON input too large");

        return AnonCredsHelpers.VerifyPresentation(
            presentation,
            presReq,
            schemasJson,
            credDefsJson,
            revRegDefsJson,
            revStatusListsJson,
            nonRevocJson
        );
    }

    // Add more higher-level methods if needed, e.g., IssueCredential flow
    public Credential IssueCredential(
        CredentialDefinition credDef,
        CredentialDefinitionPrivate credDefPvt,
        CredentialOffer offer,
        CredentialRequest request,
        string credValues,
        string? revRegId,
        string? tailsPath,
        RevocationStatusList? revStatusList
    )
    {
        if (
            credDef == null
            || credDefPvt == null
            || offer == null
            || request == null
            || string.IsNullOrEmpty(credValues)
        )
            throw new ArgumentNullException("Required parameters cannot be null or empty");
        if (credValues.Length > 100000)
            throw new ArgumentException("Credential values JSON too large");
        var (credential, _) = Credential.Create(
            credDef,
            credDefPvt,
            offer,
            request,
            credValues,
            revRegId,
            tailsPath,
            revStatusList
        );
        return credential;
    }
}
