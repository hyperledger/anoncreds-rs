using System.Runtime.InteropServices;
using AnonCredsNet.Exceptions;
using AnonCredsNet.Interop;

namespace AnonCredsNet.Models;

public class RevocationRegistryDefinition : AnonCredsObject
{
    internal RevocationRegistryDefinition(long handle)
        : base(handle) { }

    public static (RevocationRegistryDefinition, RevocationRegistryDefinitionPrivate) Create(
        CredentialDefinition credDef,
        string credDefId,
        string issuerId,
        string tag,
        string revType,
        int maxCredNum,
        string? tailsPath = null
    )
    {
        if (
            credDef == null
            || string.IsNullOrEmpty(credDefId)
            || string.IsNullOrEmpty(issuerId)
            || string.IsNullOrEmpty(tag)
            || string.IsNullOrEmpty(revType)
            || maxCredNum <= 0
        )
            throw new ArgumentNullException("Input parameters cannot be null or empty");

        var code = NativeMethods.anoncreds_create_revocation_registry_def(
            credDef.Handle,
            credDefId,
            issuerId,
            tag,
            revType,
            maxCredNum,
            tailsPath ?? string.Empty,
            out var def,
            out var pvt
        );
        if (code != ErrorCode.Success)
            throw new AnonCredsException(code, AnonCreds.GetCurrentError());
        return (
            new RevocationRegistryDefinition(def),
            new RevocationRegistryDefinitionPrivate(pvt)
        );
    }

    public string TailsLocation
    {
        get
        {
            // Prefer native getter for attribute to avoid JSON parsing mismatches
            var code = NativeMethods.anoncreds_revocation_registry_definition_get_attribute(
                this.Handle,
                "tails_location",
                out var ptr
            );
            if (code != ErrorCode.Success)
                throw new AnonCredsException(code, AnonCreds.GetCurrentError());
            try
            {
                return Marshal.PtrToStringUTF8(ptr) ?? string.Empty;
            }
            finally
            {
                NativeMethods.anoncreds_string_free(ptr);
            }
        }
    }

    public static RevocationRegistryDefinition FromJson(string json) =>
        FromJson<RevocationRegistryDefinition>(json);
}
