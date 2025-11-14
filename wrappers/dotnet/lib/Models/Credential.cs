using System.Runtime.InteropServices;
using AnonCredsNet.Exceptions;
using AnonCredsNet.Interop;
using AnonCredsNet.Requests;

namespace AnonCredsNet.Models;

public sealed class Credential : AnonCredsObject
{
    private Credential(long handle)
        : base(handle) { }

    internal static Credential FromHandle(long handle) => new Credential(handle);

    /// <summary>
    /// Creates a credential and its revocation delta. Both returned objects must be disposed using <c>using</c> statements.
    /// </summary>
    public static (Credential Credential, RevocationStatusListDelta? Delta) Create(
        CredentialDefinition credDef,
        CredentialDefinitionPrivate credDefPvt,
        CredentialOffer offer,
        CredentialRequest request,
        string credValues,
        string? revRegId,
        string? tailsPath,
        RevocationStatusList? revStatusList,
        CredentialRevocationConfig? revConfig = null
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

        // Parse credential values JSON
        var credValuesDict = System.Text.Json.JsonSerializer.Deserialize<
            Dictionary<string, string>
        >(credValues);
        if (credValuesDict == null)
            throw new ArgumentException("Invalid credential values JSON");

        var attrNames = AnonCreds.CreateFfiStrList(
            System.Text.Json.JsonSerializer.Serialize(credValuesDict.Keys)
        );
        var attrRawValues = AnonCreds.CreateFfiStrList(
            System.Text.Json.JsonSerializer.Serialize(credValuesDict.Values)
        );
        // When encoded values are not provided, pass an empty list (count=0, data=NULL)
        var attrEncValues = new FfiStrList { Count = 0, Data = IntPtr.Zero };

        // Build optional revocation info struct
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
        }
        catch
        {
            if (revocationPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(revocationPtr);
                revocationPtr = IntPtr.Zero;
            }
            throw;
        }

        try
        {
            var code = NativeMethods.anoncreds_create_credential(
                credDef.Handle,
                credDefPvt.Handle,
                offer.Handle,
                request.Handle,
                attrNames,
                attrRawValues,
                attrEncValues,
                revocationPtr,
                out var cred
            );
            if (code != ErrorCode.Success)
                throw new AnonCredsException(code, AnonCreds.GetCurrentError());
            return (new Credential(cred), null); // No delta when not using revocation
        }
        finally
        {
            AnonCreds.FreeFfiStrList(attrNames);
            AnonCreds.FreeFfiStrList(attrRawValues);
            if (revocationPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(revocationPtr);
            }
        }
    }

    public Credential Process(
        CredentialRequestMetadata credReqMetadata,
        string linkSecret,
        CredentialDefinition credDef,
        RevocationRegistryDefinition? revRegDef
    )
    {
        if (string.IsNullOrEmpty(linkSecret))
            throw new ArgumentNullException(nameof(linkSecret));
        var revRegDefHandle = revRegDef?.Handle ?? 0;
        var code = NativeMethods.anoncreds_process_credential(
            Handle,
            credReqMetadata.Handle,
            linkSecret,
            credDef.Handle,
            revRegDefHandle,
            out var newCredHandle
        );
        if (code != ErrorCode.Success)
        {
            throw new AnonCredsException(code, AnonCreds.GetCurrentError());
        }
        return new Credential(newCredHandle);
    }

    internal static Credential FromJson(string json) => FromJson<Credential>(json);
}
