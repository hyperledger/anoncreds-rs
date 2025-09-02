using AnonCredsNet.Exceptions;
using AnonCredsNet.Helpers;
using AnonCredsNet.Interop;

namespace AnonCredsNet.Objects;

public class CredentialOffer : AnonCredsObject
{
    private CredentialOffer(int handle)
        : base(handle) { }

    internal static CredentialOffer Create(CredentialDefinition credDef)
    {
        if (credDef == null)
            throw new ArgumentNullException(nameof(credDef));
        var code = NativeMethods.anoncreds_create_credential_offer(credDef.Handle, out var handle);
        if (code != ErrorCode.Success)
            throw new AnonCredsException(code, AnonCredsHelpers.GetCurrentError());
        return new CredentialOffer(handle);
    }

    internal static CredentialOffer FromJson(string json) => FromJson<CredentialOffer>(json);
}
