using AnonCredsNet.Exceptions;
using AnonCredsNet.Interop;

namespace AnonCredsNet.Models;

public class CredentialDefinition : AnonCredsObject
{
    private CredentialDefinition(long handle)
        : base(handle) { }

    public static (
        CredentialDefinition CredDef,
        CredentialDefinitionPrivate CredDefPvt,
        KeyCorrectnessProof KeyProof
    ) Create(
        string schemaId,
        string issuerId,
        Schema schema,
        string tag,
        string sigType,
        string config
    )
    {
        if (
            string.IsNullOrEmpty(schemaId)
            || string.IsNullOrEmpty(issuerId)
            || schema == null
            || string.IsNullOrEmpty(tag)
            || string.IsNullOrEmpty(sigType)
            || string.IsNullOrEmpty(config)
        )
            throw new ArgumentNullException("Input parameters cannot be null or empty");

        // Parse config to determine if revocation should be supported
        var configObj = System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement>(
            config
        );
        var supportRevocation =
            configObj.TryGetProperty("support_revocation", out var revProp) && revProp.GetBoolean();

        var code = NativeMethods.anoncreds_create_credential_definition(
            schemaId,
            schema.Handle,
            tag,
            issuerId,
            sigType,
            supportRevocation,
            out var cd,
            out var pvt,
            out var proof
        );
        if (code != ErrorCode.Success)
            throw new AnonCredsException(code, AnonCreds.GetCurrentError());
        return (
            new CredentialDefinition(cd),
            new CredentialDefinitionPrivate(pvt),
            new KeyCorrectnessProof(proof)
        );
    }

    public static CredentialDefinition FromJson(string json) =>
        FromJson<CredentialDefinition>(json);
}

public class CredentialDefinitionPrivate : AnonCredsObject
{
    internal CredentialDefinitionPrivate(long handle)
        : base(handle) { }

    internal static CredentialDefinitionPrivate FromJson(string json) =>
        FromJson<CredentialDefinitionPrivate>(json);
}
