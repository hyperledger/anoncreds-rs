using AnonCredsNet.Exceptions;
using AnonCredsNet.Interop;
using AnonCredsNet.Requests;

namespace AnonCredsNet.Models;

public sealed class W3cPresentation : AnonCredsObject
{
    private W3cPresentation(long handle)
        : base(handle) { }

    public static W3cPresentation Create(
        long presReqHandle,
        FfiCredentialEntryList credentialsList,
        FfiCredentialProveList credentialsProve,
        string linkSecret,
        FfiObjectHandleList schemasList,
        FfiStrList schemaIds,
        FfiObjectHandleList credDefsList,
        FfiStrList credDefIds,
        string? w3cVersion = null
    )
    {
        if (presReqHandle == 0 || string.IsNullOrEmpty(linkSecret))
            throw new ArgumentNullException("Invalid inputs");
        try
        {
            // Debug: dump credential entries to validate timestamp/rev_state pairing
            try
            {
                var count = (int)credentialsList.Count.ToUInt32();
                if (credentialsList.Data != IntPtr.Zero)
                {
                    var size = System.Runtime.InteropServices.Marshal.SizeOf<FfiCredentialEntry>();
                    for (int i = 0; i < count; i++)
                    {
                        var ptr = credentialsList.Data + (i * size);
                        var e =
                            System.Runtime.InteropServices.Marshal.PtrToStructure<FfiCredentialEntry>(
                                ptr
                            );
                    }
                }
            }
            catch { }
            var code = NativeMethods.anoncreds_create_w3c_presentation(
                presReqHandle,
                credentialsList,
                credentialsProve,
                linkSecret,
                schemasList,
                schemaIds,
                credDefsList,
                credDefIds,
                w3cVersion ?? "1.1",
                out var handle
            );
            if (code != ErrorCode.Success)
                throw new AnonCredsException(code, AnonCreds.GetCurrentError());
            return new W3cPresentation(handle);
        }
        finally
        {
            AnonCreds.FreeFfiObjectHandleList(schemasList);
            AnonCreds.FreeFfiObjectHandleList(credDefsList);
            AnonCreds.FreeFfiCredentialEntryList(credentialsList);
            AnonCreds.FreeFfiCredentialProveList(credentialsProve);
        }
    }

    public static W3cPresentation CreateFromJson(
        PresentationRequest presReq,
        string credentialsJson,
        string linkSecret,
        string schemasJson,
        string credDefsJson,
        string schemaIdsJson,
        string credDefIdsJson,
        string? w3cVersion = null
    )
    {
        var (schemasList, _) = AnonCreds.CreateFfiObjectHandleListWithObjects(
            schemasJson,
            Schema.FromJson
        );
        var (credDefsList, _) = AnonCreds.CreateFfiObjectHandleListWithObjects(
            credDefsJson,
            CredentialDefinition.FromJson
        );
        var credentialsList = AnonCreds.ParseCredentialsJson(credentialsJson, isW3c: true);
        var schemaIds = AnonCreds.CreateFfiStrList(schemaIdsJson);
        var credDefIds = AnonCreds.CreateFfiStrList(credDefIdsJson);
        var credentialsProve = AnonCreds.CreateCredentialsProveList(
            presReq.ToJson(),
            null,
            credentialsJson
        );

        return Create(
            presReq.Handle,
            credentialsList,
            credentialsProve,
            linkSecret,
            schemasList,
            schemaIds,
            credDefsList,
            credDefIds,
            w3cVersion
        );
    }

    public bool Verify(
        PresentationRequest presReq,
        string schemasJson,
        string credDefsJson,
        string schemaIdsJson,
        string credDefIdsJson,
        string? revRegDefsJson = null,
        string? revStatusListsJson = null,
        string? revRegDefIdsJson = null,
        string? nonRevocJson = null
    )
    {
        var (schemasList, _) = AnonCreds.CreateFfiObjectHandleListWithObjects(
            schemasJson,
            Schema.FromJson
        );
        var (credDefsList, _) = AnonCreds.CreateFfiObjectHandleListWithObjects(
            credDefsJson,
            CredentialDefinition.FromJson
        );
        var schemaIds = AnonCreds.CreateFfiStrList(schemaIdsJson);
        var credDefIds = AnonCreds.CreateFfiStrList(credDefIdsJson);

        var (revRegDefsList, _) = string.IsNullOrEmpty(revRegDefsJson)
            ? (
                new FfiObjectHandleList { Count = 0, Data = IntPtr.Zero },
                Array.Empty<RevocationRegistryDefinition>()
            )
            : AnonCreds.CreateFfiObjectHandleListWithObjects(
                revRegDefsJson,
                RevocationRegistryDefinition.FromJson
            );

        var (revStatusLists, _) = string.IsNullOrEmpty(revStatusListsJson)
            ? (
                new FfiObjectHandleList { Count = 0, Data = IntPtr.Zero },
                Array.Empty<RevocationStatusList>()
            )
            : AnonCreds.CreateFfiObjectHandleListWithObjects(
                revStatusListsJson,
                RevocationStatusList.FromJson
            );

        var revRegDefIds = !string.IsNullOrEmpty(revRegDefIdsJson)
            ? AnonCreds.CreateFfiStrList(revRegDefIdsJson)
            : new FfiStrList { Count = 0, Data = IntPtr.Zero };

        var nonRevocList = AnonCreds.BuildNonrevokedIntervalOverrideList(nonRevocJson);

        try
        {
            var code = NativeMethods.anoncreds_verify_w3c_presentation(
                Handle,
                presReq.Handle,
                schemasList,
                schemaIds,
                credDefsList,
                credDefIds,
                revRegDefsList,
                revRegDefIds,
                revStatusLists,
                nonRevocList,
                out var valid
            );
            if (code != ErrorCode.Success)
            {
                var err = AnonCreds.GetCurrentError();
                if (!string.IsNullOrEmpty(err))
                {
                    var e = err.ToLowerInvariant();
                    if (
                        e.Contains("invalid timestamp")
                        || e.Contains("proof rejected")
                        || e.Contains("credential revoked")
                        || e.Contains("revocation registry not provided")
                    )
                    {
                        return false;
                    }
                }
                throw new AnonCredsException(code, err);
            }
            return valid != 0;
        }
        finally
        {
            AnonCreds.FreeFfiObjectHandleList(schemasList);
            AnonCreds.FreeFfiObjectHandleList(credDefsList);
            AnonCreds.FreeFfiObjectHandleList(revRegDefsList);
            AnonCreds.FreeFfiObjectHandleList(revStatusLists);
            AnonCreds.FreeFfiStrList(schemaIds);
            AnonCreds.FreeFfiStrList(credDefIds);
            if (revRegDefIds.Data != IntPtr.Zero)
                AnonCreds.FreeFfiStrList(revRegDefIds);
            AnonCreds.FreeFfiNonrevokedIntervalOverrideList(nonRevocList);
        }
    }
}
