using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using AnonCredsNet.Exceptions;
using AnonCredsNet.Interop;
using AnonCredsNet.Models;
using AnonCredsNet.Requests;

namespace AnonCredsNet;

/// <summary>
/// Small utility surface mirroring python-style helpers, now the single place for FFI helpers.
/// </summary>
public static class AnonCreds
{
    // Error and nonce helpers
    internal static string GetCurrentError()
    {
        var code = NativeMethods.anoncreds_get_current_error(out var ptr);
        var error =
            code == ErrorCode.Success && ptr != IntPtr.Zero
                ? Marshal.PtrToStringUTF8(ptr) ?? "Unknown error"
                : "No error details available";
        if (ptr != IntPtr.Zero)
            NativeMethods.anoncreds_string_free(ptr);
        return error;
    }

    public static string GenerateNonce()
    {
        var code = NativeMethods.anoncreds_generate_nonce(out var ptr);
        if (code != ErrorCode.Success)
            throw new AnonCredsException(code, GetCurrentError());
        var nonce =
            Marshal.PtrToStringUTF8(ptr) ?? throw new InvalidOperationException("Null nonce");
        NativeMethods.anoncreds_string_free(ptr);
        return nonce;
    }

    // Generic FFI helpers (migrated from Helpers/AnonCredsHelpers.cs)
    internal static ByteBuffer CreateByteBuffer(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        var ptr = Marshal.AllocHGlobal(bytes.Length);
        Marshal.Copy(bytes, 0, ptr, bytes.Length);
        return new ByteBuffer { Len = bytes.Length, Data = ptr };
    }

    internal static void FreeByteBuffer(ByteBuffer buffer)
    {
        if (buffer.Data != IntPtr.Zero)
            Marshal.FreeHGlobal(buffer.Data);
    }

    internal static (FfiObjectHandleList list, T[] objects) CreateFfiObjectHandleListWithObjects<T>(
        string json,
        Func<string, T> fromJson
    )
        where T : AnonCredsObject
    {
        List<string> jsonItems = new();

        using (var doc = JsonDocument.Parse(json))
        {
            var root = doc.RootElement;
            if (root.ValueKind == JsonValueKind.Array)
            {
                foreach (var el in root.EnumerateArray())
                {
                    if (el.ValueKind == JsonValueKind.String)
                        jsonItems.Add(
                            el.GetString()
                                ?? throw new InvalidOperationException("Null string element")
                        );
                    else
                        jsonItems.Add(el.GetRawText());
                }
            }
            else if (root.ValueKind == JsonValueKind.Object)
            {
                foreach (var prop in root.EnumerateObject())
                {
                    var val = prop.Value;
                    if (val.ValueKind == JsonValueKind.String)
                        jsonItems.Add(
                            val.GetString()
                                ?? throw new InvalidOperationException("Null string value")
                        );
                    else
                        jsonItems.Add(val.GetRawText());
                }
            }
            else
            {
                throw new InvalidOperationException("Invalid JSON shape for object handle list");
            }
        }

        var objectHandles = new long[jsonItems.Count];
        var managedObjects = new T[jsonItems.Count];

        for (var i = 0; i < jsonItems.Count; i++)
        {
            var item = fromJson(jsonItems[i]);
            managedObjects[i] = item;
            objectHandles[i] = item.Handle;
        }

        var ptr = Marshal.AllocHGlobal(jsonItems.Count * Marshal.SizeOf<long>());
        Marshal.Copy(objectHandles, 0, ptr, jsonItems.Count);

        var list = new FfiObjectHandleList { Count = (nuint)jsonItems.Count, Data = ptr };
        return (list, managedObjects);
    }

    internal static FfiObjectHandleList CreateFfiObjectHandleList<T>(
        string json,
        Func<string, T> fromJson
    )
        where T : AnonCredsObject
    {
        var (list, _) = CreateFfiObjectHandleListWithObjects(json, fromJson);
        return list;
    }

    internal static void FreeFfiObjectHandleList(FfiObjectHandleList list)
    {
        if (list.Data != IntPtr.Zero)
            Marshal.FreeHGlobal(list.Data);
    }

    internal static FfiStrList CreateFfiStrList(string json)
    {
        var strings =
            JsonSerializer.Deserialize<string[]>(json)
            ?? throw new InvalidOperationException("Invalid JSON array");
        var ptrs = new IntPtr[strings.Length];
        for (var i = 0; i < strings.Length; i++)
        {
            var utf8 = Encoding.UTF8.GetBytes(strings[i] + "\0");
            var p = Marshal.AllocHGlobal(utf8.Length);
            Marshal.Copy(utf8, 0, p, utf8.Length);
            ptrs[i] = p;
        }
        var listPtr = Marshal.AllocHGlobal(strings.Length * IntPtr.Size);
        Marshal.Copy(ptrs, 0, listPtr, strings.Length);
        return new FfiStrList { Count = (nuint)strings.Length, Data = listPtr };
    }

    internal static FfiStrList CreateFfiStrListFromStrings(string[] strings)
    {
        var ptrs = new IntPtr[strings.Length];
        for (var i = 0; i < strings.Length; i++)
        {
            var utf8 = Encoding.UTF8.GetBytes(strings[i] + "\0");
            var p = Marshal.AllocHGlobal(utf8.Length);
            Marshal.Copy(utf8, 0, p, utf8.Length);
            ptrs[i] = p;
        }
        var listPtr = Marshal.AllocHGlobal(strings.Length * IntPtr.Size);
        Marshal.Copy(ptrs, 0, listPtr, strings.Length);
        return new FfiStrList { Count = (nuint)strings.Length, Data = listPtr };
    }

    internal static void FreeFfiStrList(FfiStrList list)
    {
        if (list.Data != IntPtr.Zero)
        {
            var count = (int)list.Count.ToUInt32();
            for (var i = 0; i < count; i++)
            {
                var strPtr = Marshal.ReadIntPtr(list.Data, i * IntPtr.Size);
                Marshal.FreeHGlobal(strPtr);
            }
            Marshal.FreeHGlobal(list.Data);
        }
    }

    internal static FfiInt32List CreateFfiInt32List(ulong[]? values)
    {
        if (values == null || values.Length == 0)
            return new FfiInt32List { Count = 0, Data = IntPtr.Zero };
        var ints = values.Select(v => unchecked((int)v)).ToArray();
        var size = sizeof(int) * ints.Length;
        var ptr = Marshal.AllocHGlobal(size);
        Marshal.Copy(ints, 0, ptr, ints.Length);
        return new FfiInt32List { Count = (nuint)ints.Length, Data = ptr };
    }

    internal static void FreeFfiCredentialEntryList(FfiCredentialEntryList list)
    {
        if (list.Data != IntPtr.Zero)
            Marshal.FreeHGlobal(list.Data);
    }

    private class CredentialEntryJson
    {
        public string Credential { get; set; } = "";
        public int? Timestamp { get; set; }

        [JsonPropertyName("rev_state")]
        public string? RevState { get; set; }

        [JsonPropertyName("referents")]
        public List<string>? Referents { get; set; }
    }

    internal static FfiCredentialEntryList ParseCredentialsJson(
        string credentialsJson,
        bool isW3c = false
    )
    {
        var entries =
            JsonSerializer.Deserialize<CredentialEntryJson[]>(
                credentialsJson,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
            ) ?? throw new InvalidOperationException("Invalid credentials JSON");
        var ffiEntries = new FfiCredentialEntry[entries.Length];
        for (var i = 0; i < entries.Length; i++)
        {
            var entry = entries[i];
            var credBuffer = CreateByteBuffer(entry.Credential);
            long credHandle;
            ErrorCode result;
            try
            {
                if (isW3c)
                    result = NativeMethods.anoncreds_w3c_credential_from_json(
                        credBuffer,
                        out credHandle
                    );
                else
                    result = NativeMethods.anoncreds_credential_from_json(
                        credBuffer,
                        out credHandle
                    );
            }
            finally
            {
                FreeByteBuffer(credBuffer);
            }
            if (result != ErrorCode.Success)
                throw new AnonCredsException(result, GetCurrentError());

            long revStateHandle = 0;
            if (!string.IsNullOrEmpty(entry.RevState))
            {
                var revStateBuffer = CreateByteBuffer(entry.RevState);
                try
                {
                    result = NativeMethods.anoncreds_revocation_state_from_json(
                        revStateBuffer,
                        out revStateHandle
                    );
                }
                finally
                {
                    FreeByteBuffer(revStateBuffer);
                }
                if (result != ErrorCode.Success)
                    throw new AnonCredsException(result, GetCurrentError());
            }

            ffiEntries[i] = new FfiCredentialEntry
            {
                Credential = credHandle,
                Timestamp = entry.Timestamp.HasValue ? entry.Timestamp.Value : -1,
                RevState = revStateHandle,
            };
        }
        var ptr = Marshal.AllocHGlobal(ffiEntries.Length * Marshal.SizeOf<FfiCredentialEntry>());
        for (var i = 0; i < ffiEntries.Length; i++)
        {
            Marshal.StructureToPtr(
                ffiEntries[i],
                ptr + i * Marshal.SizeOf<FfiCredentialEntry>(),
                false
            );
        }
        return new FfiCredentialEntryList { Data = ptr, Count = (nuint)ffiEntries.Length };
    }

    internal static FfiCredentialProveList CreateCredentialsProveList(
        string presReqJson,
        string? selfAttestJson,
        string? credentialsJson
    )
    {
        var proveList = new List<FfiCredentialProve>();
        Dictionary<string, int> referentToEntryIdx = new(StringComparer.Ordinal);
        if (!string.IsNullOrEmpty(credentialsJson))
        {
            try
            {
                var entries = JsonSerializer.Deserialize<CredentialEntryJson[]>(
                    credentialsJson,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                );
                if (entries != null)
                {
                    for (int i = 0; i < entries.Length; i++)
                    {
                        var refs = entries[i].Referents;
                        if (refs == null)
                            continue;
                        foreach (var r in refs)
                            if (!referentToEntryIdx.ContainsKey(r))
                                referentToEntryIdx[r] = i;
                    }
                }
            }
            catch { }
        }

        HashSet<string> selfAttestedReferents = new(StringComparer.Ordinal);
        if (!string.IsNullOrEmpty(selfAttestJson))
        {
            try
            {
                var map =
                    JsonSerializer.Deserialize<Dictionary<string, string>>(selfAttestJson!)
                    ?? new();
                foreach (var k in map.Keys)
                    selfAttestedReferents.Add(k);
            }
            catch { }
        }

        using (var doc = JsonDocument.Parse(presReqJson))
        {
            var root = doc.RootElement;
            if (root.TryGetProperty("requested_attributes", out var requestedAttributes))
            {
                foreach (var attr in requestedAttributes.EnumerateObject())
                {
                    var referent = attr.Name;
                    if (selfAttestedReferents.Contains(referent))
                        continue;
                    int entryIdx = referentToEntryIdx.TryGetValue(referent, out var idx) ? idx : 0;
                    proveList.Add(
                        new FfiCredentialProve
                        {
                            EntryIdx = entryIdx,
                            Referent = Marshal.StringToHGlobalAnsi(referent),
                            IsPredicate = 0,
                            Reveal = 1,
                        }
                    );
                }
            }
            if (root.TryGetProperty("requested_predicates", out var requestedPredicates))
            {
                foreach (var pred in requestedPredicates.EnumerateObject())
                {
                    var referent = pred.Name;
                    int entryIdx = referentToEntryIdx.TryGetValue(referent, out var idx) ? idx : 0;
                    proveList.Add(
                        new FfiCredentialProve
                        {
                            EntryIdx = entryIdx,
                            Referent = Marshal.StringToHGlobalAnsi(referent),
                            IsPredicate = 1,
                            Reveal = 0,
                        }
                    );
                }
            }
        }

        if (proveList.Count == 0)
            return new FfiCredentialProveList { Data = IntPtr.Zero, Count = 0 };

        var proveArray = proveList.ToArray();
        var size = Marshal.SizeOf<FfiCredentialProve>();
        var ptr = Marshal.AllocHGlobal(size * proveArray.Length);
        for (int i = 0; i < proveArray.Length; i++)
            Marshal.StructureToPtr(proveArray[i], ptr + (i * size), false);
        return new FfiCredentialProveList { Data = ptr, Count = (nuint)proveArray.Length };
    }

    internal static void FreeFfiCredentialProveList(FfiCredentialProveList list)
    {
        if (list.Data != IntPtr.Zero)
        {
            var count = (int)list.Count.ToUInt32();
            for (var i = 0; i < count; i++)
            {
                var provePtr = list.Data + i * Marshal.SizeOf<FfiCredentialProve>();
                var prove = Marshal.PtrToStructure<FfiCredentialProve>(provePtr);
                if (prove.Referent != IntPtr.Zero)
                    Marshal.FreeHGlobal(prove.Referent);
            }
            Marshal.FreeHGlobal(list.Data);
        }
    }

    internal static FfiNonrevokedIntervalOverrideList BuildNonrevokedIntervalOverrideList(
        string? nonRevocJson
    )
    {
        if (string.IsNullOrWhiteSpace(nonRevocJson))
            return new FfiNonrevokedIntervalOverrideList { Count = 0, Data = IntPtr.Zero };

        var overrides = new List<FfiNonrevokedIntervalOverride>();
        using var doc = JsonDocument.Parse(nonRevocJson);
        var root = doc.RootElement;
        if (root.ValueKind == JsonValueKind.Object)
        {
            foreach (var revMap in root.EnumerateObject())
            {
                var revRegId = revMap.Name;
                if (revMap.Value.ValueKind == JsonValueKind.Object)
                {
                    foreach (var tsMap in revMap.Value.EnumerateObject())
                    {
                        if (!int.TryParse(tsMap.Name, out var fromTs))
                            continue;
                        var overrideTs = tsMap.Value.GetInt32();
                        var idPtr = Marshal.StringToHGlobalAnsi(revRegId);
                        overrides.Add(
                            new FfiNonrevokedIntervalOverride
                            {
                                RevRegDefId = idPtr,
                                RequestedFromTs = fromTs,
                                OverrideRevStatusListTs = overrideTs,
                            }
                        );
                    }
                }
            }
        }
        else if (root.ValueKind == JsonValueKind.Array)
        {
            foreach (var el in root.EnumerateArray())
            {
                var revRegId = el.GetProperty("revRegId").GetString() ?? string.Empty;
                var fromTs = el.GetProperty("requested_from_ts").GetInt32();
                var overrideTs = el.GetProperty("override_ts").GetInt32();
                var idPtr = Marshal.StringToHGlobalAnsi(revRegId);
                overrides.Add(
                    new FfiNonrevokedIntervalOverride
                    {
                        RevRegDefId = idPtr,
                        RequestedFromTs = fromTs,
                        OverrideRevStatusListTs = overrideTs,
                    }
                );
            }
        }

        if (overrides.Count == 0)
            return new FfiNonrevokedIntervalOverrideList { Count = 0, Data = IntPtr.Zero };

        var size = Marshal.SizeOf<FfiNonrevokedIntervalOverride>();
        var ptr = Marshal.AllocHGlobal(size * overrides.Count);
        for (int i = 0; i < overrides.Count; i++)
            Marshal.StructureToPtr(overrides[i], ptr + (i * size), false);
        return new FfiNonrevokedIntervalOverrideList { Count = (nuint)overrides.Count, Data = ptr };
    }

    internal static void FreeFfiNonrevokedIntervalOverrideList(
        FfiNonrevokedIntervalOverrideList list
    )
    {
        if (list.Data == IntPtr.Zero || list.Count == 0)
            return;
        var size = Marshal.SizeOf<FfiNonrevokedIntervalOverride>();
        var count = (int)list.Count.ToUInt32();
        for (int i = 0; i < count; i++)
        {
            var ptr = list.Data + (i * size);
            var item = Marshal.PtrToStructure<FfiNonrevokedIntervalOverride>(ptr);
            if (item.RevRegDefId != IntPtr.Zero)
                Marshal.FreeHGlobal(item.RevRegDefId);
        }
        Marshal.FreeHGlobal(list.Data);
    }

    // Classic presentations (Python-style convenience)
    public static Presentation CreatePresentationFromJson(
        PresentationRequest presReq,
        string credentialsJson,
        string? selfAttestJson,
        string linkSecret,
        string schemasJson,
        string credDefsJson,
        string schemaIdsJson,
        string credDefIdsJson,
        string? revRegDefsJson = null,
        string? revStatusListsJson = null
    )
    {
        return Presentation.CreateFromJson(
            presReq,
            credentialsJson,
            selfAttestJson,
            linkSecret,
            schemasJson,
            credDefsJson,
            schemaIdsJson,
            credDefIdsJson,
            revRegDefsJson,
            revStatusListsJson
        );
    }

    public static bool VerifyPresentation(
        Presentation presentation,
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
        var (schemasList, _) = CreateFfiObjectHandleListWithObjects(schemasJson, Schema.FromJson);
        var (credDefsList, _) = CreateFfiObjectHandleListWithObjects(
            credDefsJson,
            CredentialDefinition.FromJson
        );
        var schemaIds = CreateFfiStrList(schemaIdsJson);
        var credDefIds = CreateFfiStrList(credDefIdsJson);

        var (revRegDefsList, _) = string.IsNullOrEmpty(revRegDefsJson)
            ? (
                new FfiObjectHandleList { Count = 0, Data = IntPtr.Zero },
                Array.Empty<RevocationRegistryDefinition>()
            )
            : CreateFfiObjectHandleListWithObjects(
                revRegDefsJson!,
                RevocationRegistryDefinition.FromJson
            );
        var (revStatusLists, _) = string.IsNullOrEmpty(revStatusListsJson)
            ? (
                new FfiObjectHandleList { Count = 0, Data = IntPtr.Zero },
                Array.Empty<RevocationStatusList>()
            )
            : CreateFfiObjectHandleListWithObjects(
                revStatusListsJson!,
                RevocationStatusList.FromJson
            );

        var revRegDefIds = !string.IsNullOrEmpty(revRegDefIdsJson)
            ? CreateFfiStrList(revRegDefIdsJson!)
            : new FfiStrList { Count = 0, Data = IntPtr.Zero };

        var nonRevocList = BuildNonrevokedIntervalOverrideList(nonRevocJson);

        try
        {
            var code = NativeMethods.anoncreds_verify_presentation(
                presentation.Handle,
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
                var err = GetCurrentError();
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
            FreeFfiObjectHandleList(schemasList);
            FreeFfiObjectHandleList(credDefsList);
            FreeFfiObjectHandleList(revRegDefsList);
            FreeFfiObjectHandleList(revStatusLists);
            FreeFfiStrList(schemaIds);
            FreeFfiStrList(credDefIds);
            if (revRegDefIds.Data != IntPtr.Zero)
                FreeFfiStrList(revRegDefIds);
            FreeFfiNonrevokedIntervalOverrideList(nonRevocList);
        }
    }

    // W3C presentations (Python-style convenience)
    public static W3cPresentation CreateW3cPresentationFromJson(
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
        return W3cPresentation.CreateFromJson(
            presReq,
            credentialsJson,
            linkSecret,
            schemasJson,
            credDefsJson,
            schemaIdsJson,
            credDefIdsJson,
            w3cVersion
        );
    }

    public static bool VerifyW3cPresentation(
        W3cPresentation presentation,
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
        return presentation.Verify(
            presReq,
            schemasJson,
            credDefsJson,
            schemaIdsJson,
            credDefIdsJson,
            revRegDefsJson,
            revStatusListsJson,
            revRegDefIdsJson,
            nonRevocJson
        );
    }
}
