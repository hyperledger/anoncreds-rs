using AnonCredsNet.Exceptions;
using AnonCredsNet.Helpers;
using AnonCredsNet.Interop;
using AnonCredsNet.Requests;

namespace AnonCredsNet.Objects;

public sealed class Presentation : AnonCredsObject
{
    private Presentation(int handle)
        : base(handle) { }

    /// <summary>
    /// Creates a presentation. The returned object must be disposed using a <c>using</c> statement.
    /// </summary>
    public static Presentation Create(
        string presReqJson,
        string credentialsJson,
        string? selfAttestJson,
        LinkSecret linkSecret,
        string schemasJson,
        string credDefsJson
    )
    {
        if (
            string.IsNullOrEmpty(presReqJson)
            || string.IsNullOrEmpty(credentialsJson)
            || linkSecret == null
            || string.IsNullOrEmpty(schemasJson)
            || string.IsNullOrEmpty(credDefsJson)
        )
            throw new ArgumentNullException("Input parameters cannot be null or empty");
        if (linkSecret.Handle == 0)
            throw new ObjectDisposedException(nameof(LinkSecret));

        var presReq = PresentationRequest.FromJson(presReqJson);
        var schemasList = AnonCredsHelpers.CreateFfiList(schemasJson, Schema.FromJson);
        var credDefsList = AnonCredsHelpers.CreateFfiList(
            credDefsJson,
            CredentialDefinition.FromJson
        );
        var credentialsList = AnonCredsHelpers.CreateFfiList(credentialsJson, Credential.FromJson);

        try
        {
            var code = NativeMethods.anoncreds_create_presentation(
                presReq.Handle,
                credentialsList,
                selfAttestJson ?? "{}",
                linkSecret.Handle,
                schemasList,
                credDefsList,
                out var handle
            );
            if (code != ErrorCode.Success)
                throw new AnonCredsException(code, AnonCredsHelpers.GetCurrentError());
            return new Presentation(handle);
        }
        finally
        {
            presReq.Dispose();
            AnonCredsHelpers.FreeFfiList(schemasList);
            AnonCredsHelpers.FreeFfiList(credDefsList);
            AnonCredsHelpers.FreeFfiList(credentialsList);
        }
    }

    public static Presentation FromJson(string json) => FromJson<Presentation>(json);
}
