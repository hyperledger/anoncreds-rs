using AnonCredsNet.Exceptions;
using AnonCredsNet.Interop;

namespace AnonCredsNet.Models;

public class CredentialOffer : AnonCredsObject
{
    private CredentialOffer(long handle)
        : base(handle) { }

    public static CredentialOffer Create(
        string schemaId,
        string credDefId,
        KeyCorrectnessProof keyProof
    )
    {
        if (string.IsNullOrEmpty(schemaId))
            throw new ArgumentNullException(nameof(schemaId));
        if (string.IsNullOrEmpty(credDefId))
            throw new ArgumentNullException(nameof(credDefId));
        if (keyProof == null)
            throw new ArgumentNullException(nameof(keyProof));
        var code = NativeMethods.anoncreds_create_credential_offer(
            schemaId,
            credDefId,
            keyProof.Handle,
            out var handle
        );
        if (code != ErrorCode.Success)
            throw new AnonCredsException(code, AnonCreds.GetCurrentError());
        return new CredentialOffer(handle);
    }

    internal static CredentialOffer FromJson(string json) => FromJson<CredentialOffer>(json);
}
