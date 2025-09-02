using AnonCredsNet.Exceptions;
using AnonCredsNet.Helpers;
using AnonCredsNet.Interop;
using AnonCredsNet.Requests;

namespace AnonCredsNet.Objects;

public sealed class Credential : AnonCredsObject
{
    private Credential(int handle)
        : base(handle) { }

    /// <summary>
    /// Creates a credential and its revocation delta. Both returned objects must be disposed using <c>using</c> statements.
    /// </summary>
    internal static (Credential Credential, RevocationStatusListDelta Delta) Create(
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
            throw new ArgumentNullException("Input parameters cannot be null or empty");
        var code = NativeMethods.anoncreds_create_credential(
            credDef.Handle,
            credDefPvt.Handle,
            offer.Handle,
            request.Handle,
            credValues,
            revRegId ?? "",
            tailsPath ?? "",
            revStatusList?.Handle ?? 0,
            out var cred,
            out var delta
        );
        if (code != ErrorCode.Success)
            throw new AnonCredsException(code, AnonCredsHelpers.GetCurrentError());
        return (new Credential(cred), new RevocationStatusListDelta(delta));
    }

    internal static Credential Process(
        Credential credential,
        CredentialRequestMetadata metadata,
        LinkSecret linkSecret,
        CredentialDefinition credDef,
        RevocationRegistryDefinition? revRegDef
    )
    {
        if (credential == null || metadata == null || linkSecret == null || credDef == null)
            throw new ArgumentNullException("Input parameters cannot be null");
        if (credential.Handle == 0)
            throw new ObjectDisposedException(nameof(Credential));
        var code = NativeMethods.anoncreds_process_credential(
            credential.Handle,
            metadata.Handle,
            linkSecret.Handle,
            credDef.Handle,
            revRegDef?.Handle ?? 0,
            out var processed
        );
        if (code != ErrorCode.Success)
            throw new AnonCredsException(code, AnonCredsHelpers.GetCurrentError());
        return new Credential(processed);
    }

    internal static Credential FromJson(string json) => FromJson<Credential>(json);
}
