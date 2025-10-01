using System.Runtime.InteropServices;
using AnonCredsNet.Exceptions;
using AnonCredsNet.Interop;
using AnonCredsNet.Requests;

namespace AnonCredsNet.Models;

public sealed class W3cCredential : AnonCredsObject
{
    private W3cCredential(long handle)
        : base(handle) { }

    public static W3cCredential Create(
        CredentialDefinition credDef,
        CredentialDefinitionPrivate credDefPvt,
        CredentialOffer offer,
        CredentialRequest request,
        string credValues,
        CredentialRevocationConfig? revConfig,
        string? w3cVersion
    )
    {
        if (string.IsNullOrEmpty(credValues))
            throw new ArgumentNullException(nameof(credValues));

        var dict =
            System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(credValues)
            ?? throw new ArgumentException("Invalid credential values JSON");
        var attrNames = AnonCreds.CreateFfiStrList(
            System.Text.Json.JsonSerializer.Serialize(dict.Keys)
        );
        var attrRawValues = AnonCreds.CreateFfiStrList(
            System.Text.Json.JsonSerializer.Serialize(dict.Values)
        );

        IntPtr revocationPtr = IntPtr.Zero;
        try
        {
            if (
                revConfig != null
                && revConfig.RevRegDef != null
                && revConfig.RevRegDefPrivate != null
                && revConfig.RevStatusList != null
            )
            {
                var revInfo = new FfiCredRevInfo
                {
                    RegDef = revConfig.RevRegDef.Handle,
                    RegDefPrivate = revConfig.RevRegDefPrivate.Handle,
                    StatusList = revConfig.RevStatusList.Handle,
                    RegIdx = (long)revConfig.RevRegIndex,
                };
                revocationPtr = Marshal.AllocHGlobal(Marshal.SizeOf<FfiCredRevInfo>());
                Marshal.StructureToPtr(revInfo, revocationPtr, false);
            }

            var code = NativeMethods.anoncreds_create_w3c_credential(
                credDef.Handle,
                credDefPvt.Handle,
                offer.Handle,
                request.Handle,
                attrNames,
                attrRawValues,
                revocationPtr,
                w3cVersion ?? "1.1",
                out var cred
            );
            if (code != ErrorCode.Success)
                throw new AnonCredsException(code, AnonCreds.GetCurrentError());
            return new W3cCredential(cred);
        }
        finally
        {
            AnonCreds.FreeFfiStrList(attrNames);
            AnonCreds.FreeFfiStrList(attrRawValues);
            if (revocationPtr != IntPtr.Zero)
                Marshal.FreeHGlobal(revocationPtr);
        }
    }

    public W3cCredential Process(
        CredentialRequestMetadata credReqMetadata,
        string linkSecret,
        CredentialDefinition credDef,
        RevocationRegistryDefinition? revRegDef
    )
    {
        var code = NativeMethods.anoncreds_process_w3c_credential(
            Handle,
            credReqMetadata.Handle,
            linkSecret,
            credDef.Handle,
            revRegDef?.Handle ?? 0,
            out var handle
        );
        if (code != ErrorCode.Success)
            throw new AnonCredsException(code, AnonCreds.GetCurrentError());
        return new W3cCredential(handle);
    }

    public static W3cCredential FromJson(string json) => FromJson<W3cCredential>(json);

    public Credential ToLegacy()
    {
        var code = NativeMethods.anoncreds_credential_from_w3c(Handle, out var legacy);
        if (code != ErrorCode.Success)
            throw new AnonCredsException(code, AnonCreds.GetCurrentError());
        return Credential.FromHandle(legacy);
    }

    public static W3cCredential FromLegacy(
        Credential legacy,
        string issuerId,
        string? w3cVersion = null
    )
    {
        var code = NativeMethods.anoncreds_credential_to_w3c(
            legacy.Handle,
            issuerId,
            w3cVersion ?? "1.1",
            out var w3c
        );
        if (code != ErrorCode.Success)
            throw new AnonCredsException(code, AnonCreds.GetCurrentError());
        return new W3cCredential(w3c);
    }
}
