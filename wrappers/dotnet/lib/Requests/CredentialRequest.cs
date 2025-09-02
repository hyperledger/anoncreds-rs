using AnonCredsNet.Exceptions;
using AnonCredsNet.Helpers;
using AnonCredsNet.Interop;
using AnonCredsNet.Objects;

namespace AnonCredsNet.Requests;

public class CredentialRequest : AnonCredsObject
{
    private CredentialRequest(int handle)
        : base(handle) { }

    internal static (CredentialRequest Request, CredentialRequestMetadata Metadata) Create(
        CredentialDefinition credDef,
        LinkSecret linkSecret,
        string linkSecretId,
        CredentialOffer credOffer
    )
    {
        if (
            credDef == null
            || linkSecret == null
            || string.IsNullOrEmpty(linkSecretId)
            || credOffer == null
        )
            throw new ArgumentNullException("Input parameters cannot be null or empty");
        var code = NativeMethods.anoncreds_create_credential_request(
            credDef.Handle,
            linkSecret.Handle,
            linkSecretId,
            credOffer.Handle,
            out var req,
            out var meta
        );
        if (code != ErrorCode.Success)
            throw new AnonCredsException(code, AnonCredsHelpers.GetCurrentError());
        return (new CredentialRequest(req), new CredentialRequestMetadata(meta));
    }

    internal static CredentialRequest FromJson(string json) => FromJson<CredentialRequest>(json);
}
