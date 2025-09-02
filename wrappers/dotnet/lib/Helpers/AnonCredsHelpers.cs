using System.Runtime.InteropServices;
using System.Text.Json;
using AnonCredsNet.Exceptions;
using AnonCredsNet.Interop;
using AnonCredsNet.Objects;
using AnonCredsNet.Requests;

namespace AnonCredsNet.Helpers;

internal static class AnonCredsHelpers
{
    private static bool _initialized;

    internal static void Initialize()
    {
        if (_initialized)
            return;
        // No explicit initialization in anoncreds-rs FFI, but placeholder for future use
        _initialized = true;
    }

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

    internal static string GenerateNonce()
    {
        var code = NativeMethods.anoncreds_generate_nonce(out var ptr);
        if (code != ErrorCode.Success)
            throw new AnonCredsException(code, GetCurrentError());
        var nonce =
            Marshal.PtrToStringUTF8(ptr) ?? throw new InvalidOperationException("Null nonce");
        NativeMethods.anoncreds_string_free(ptr);
        return nonce;
    }

    internal static FfiList CreateFfiList<T>(string json, Func<string, T> fromJson)
        where T : AnonCredsObject
    {
        var items =
            JsonSerializer.Deserialize<string[]>(json)
            ?? throw new InvalidOperationException("Invalid JSON array");
        var handles = new int[items.Length];
        for (var i = 0; i < items.Length; i++)
        {
            var item = fromJson(items[i]);
            handles[i] = item.Handle;
            item.Dispose(); // Dispose after capturing handle
        }
        var ptr = Marshal.AllocHGlobal(handles.Length * sizeof(int));
        Marshal.Copy(handles, 0, ptr, handles.Length);
        return new FfiList { Handles = ptr, Count = handles.Length };
    }

    internal static void FreeFfiList(FfiList list)
    {
        if (list.Handles != IntPtr.Zero)
            Marshal.FreeHGlobal(list.Handles);
    }

    /// <summary>
    /// Verifies a presentation. Ensure the <see cref="Presentation"/> and <see cref="PresentationRequest"/> are disposed after use.
    /// </summary>
    public static bool VerifyPresentation(
        Presentation presentation,
        PresentationRequest presReq,
        string schemasJson,
        string credDefsJson,
        string? revRegDefsJson,
        string? revStatusListsJson,
        string? nonRevocJson
    )
    {
        if (
            presentation == null
            || presReq == null
            || string.IsNullOrEmpty(schemasJson)
            || string.IsNullOrEmpty(credDefsJson)
        )
            throw new ArgumentNullException("Required parameters cannot be null or empty");
        if (presentation.Handle == 0 || presReq.Handle == 0)
            throw new ObjectDisposedException("Presentation or PresentationRequest is disposed");
        if (schemasJson.Length > 100000 || credDefsJson.Length > 100000)
            throw new ArgumentException("JSON input too large");

        var schemasList = CreateFfiList(schemasJson, Schema.FromJson);
        var credDefsList = CreateFfiList(credDefsJson, CredentialDefinition.FromJson);
        var revRegDefsList = string.IsNullOrEmpty(revRegDefsJson)
            ? new FfiList()
            : CreateFfiList(revRegDefsJson, RevocationRegistryDefinition.FromJson);
        var revStatusLists = string.IsNullOrEmpty(revStatusListsJson)
            ? new FfiList()
            : CreateFfiList(revStatusListsJson, RevocationStatusList.FromJson);
        var nonRevocList = new FfiList(); // Empty list, as non-revocation proof is not supported

        try
        {
            var code = NativeMethods.anoncreds_verify_presentation(
                presentation.Handle,
                presReq.Handle,
                schemasList,
                credDefsList,
                revRegDefsList,
                revStatusLists,
                nonRevocList,
                out var valid
            );
            if (code != ErrorCode.Success)
                throw new AnonCredsException(code, GetCurrentError());
            return valid;
        }
        finally
        {
            FreeFfiList(schemasList);
            FreeFfiList(credDefsList);
            FreeFfiList(revRegDefsList);
            FreeFfiList(revStatusLists);
            FreeFfiList(nonRevocList);
        }
    }
}
