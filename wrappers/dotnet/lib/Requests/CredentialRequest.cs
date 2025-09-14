using AnonCredsNet.Exceptions;
using AnonCredsNet.Interop;
using AnonCredsNet.Models;

namespace AnonCredsNet.Requests;

public class CredentialRequest : AnonCredsObject
{
    private CredentialRequest(long handle)
        : base(handle) { }

    public static (CredentialRequest Request, CredentialRequestMetadata Metadata) Create(
        CredentialDefinition credDef,
        string linkSecret,
        string linkSecretId,
        CredentialOffer credOffer,
        string? entropy = null,
        string? proverDid = null
    )
    {
        if (
            credDef == null
            || string.IsNullOrEmpty(linkSecret)
            || string.IsNullOrEmpty(linkSecretId)
            || credOffer == null
        )
            throw new ArgumentNullException("Input parameters cannot be null or empty");
        var code = NativeMethods.anoncreds_create_credential_request(
            entropy,
            proverDid,
            credDef.Handle,
            linkSecret,
            linkSecretId,
            credOffer.Handle,
            out var req,
            out var meta
        );
        if (code != ErrorCode.Success)
            throw new AnonCredsException(code, AnonCreds.GetCurrentError());
        return (new CredentialRequest(req), new CredentialRequestMetadata(meta));
    }

    internal static CredentialRequest FromJson(string json) => FromJson<CredentialRequest>(json);
}
