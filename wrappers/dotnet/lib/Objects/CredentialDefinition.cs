using AnonCredsNet.Exceptions;
using AnonCredsNet.Helpers;
using AnonCredsNet.Interop;

namespace AnonCredsNet.Objects;

public class CredentialDefinition : AnonCredsObject
{
    private CredentialDefinition(int handle)
        : base(handle) { }

    internal static (
        CredentialDefinition CredDef,
        CredentialDefinitionPrivate CredDefPvt,
        KeyCorrectnessProof KeyProof
    ) Create(string issuerId, Schema schema, string tag, string sigType, string config)
    {
        if (
            string.IsNullOrEmpty(issuerId)
            || schema == null
            || string.IsNullOrEmpty(tag)
            || string.IsNullOrEmpty(sigType)
            || string.IsNullOrEmpty(config)
        )
            throw new ArgumentNullException("Input parameters cannot be null or empty");
        var code = NativeMethods.anoncreds_create_credential_definition(
            issuerId,
            schema.Handle,
            tag,
            sigType,
            config,
            out var cd,
            out var pvt,
            out var proof
        );
        if (code != ErrorCode.Success)
            throw new AnonCredsException(code, AnonCredsHelpers.GetCurrentError());
        return (
            new CredentialDefinition(cd),
            new CredentialDefinitionPrivate(pvt),
            new KeyCorrectnessProof(proof)
        );
    }

    internal static CredentialDefinition FromJson(string json) =>
        FromJson<CredentialDefinition>(json);
}

public class CredentialDefinitionPrivate : AnonCredsObject
{
    internal CredentialDefinitionPrivate(int handle)
        : base(handle) { }

    internal static CredentialDefinitionPrivate FromJson(string json) =>
        FromJson<CredentialDefinitionPrivate>(json);
}
