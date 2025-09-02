// NativeMethods.cs
using System.Runtime.InteropServices;

namespace AnonCredsNet.Interop;

internal static partial class NativeMethods
{
    private const string Library = "anoncreds";

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_get_current_error(out IntPtr errorJson);

    [LibraryImport(Library)]
    internal static partial void anoncreds_string_free(IntPtr str);

    [LibraryImport(Library)]
    internal static partial void anoncreds_buffer_free(ByteBuffer buf);

    [LibraryImport(Library)]
    internal static partial void anoncreds_object_free(int handle);

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_object_get_json(int handle, out IntPtr json);

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_object_from_json(string json, out int handle);

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_generate_nonce(out IntPtr nonce);

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_create_schema(
        string issuerId,
        string name,
        string version,
        string attrNames,
        out int handle
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_create_credential_definition(
        string issuerId,
        int schema,
        string tag,
        string sigType,
        string config,
        out int credDef,
        out int credDefPvt,
        out int keyProof
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_create_credential_offer(int credDef, out int offer);

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_create_link_secret(out int linkSecret);

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_create_credential_request(
        int credDef,
        int linkSecret,
        string linkSecretId,
        int credOffer,
        out int request,
        out int metadata
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_create_credential(
        int credDef,
        int credDefPvt,
        int credOffer,
        int credRequest,
        string credValues,
        string revRegId,
        string tailsPath,
        int revStatusList,
        out int credential,
        out int revStatusListDelta
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_process_credential(
        int credential,
        int requestMetadata,
        int linkSecret,
        int credDef,
        int revRegDef,
        out int processedCredential
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_create_presentation(
        int presReq,
        FfiList credentials,
        string selfAttestJson,
        int linkSecret,
        FfiList schemas,
        FfiList credDefs,
        out int presentation
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_verify_presentation(
        int presentation,
        int presReq,
        FfiList schemas,
        FfiList credDefs,
        FfiList revRegDefs,
        FfiList revStatusLists,
        FfiList nonRevoc,
        [MarshalAs(UnmanagedType.U1)] out bool isValid
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_create_revocation_registry_def(
        int credDef,
        string issuerId,
        string tag,
        string revType,
        string config,
        string tailsPath,
        out int revRegDef,
        out int revRegPvt,
        out int revStatusList
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_create_revocation_status_list(
        string issuerId,
        int revRegDef,
        string timestamp,
        [MarshalAs(UnmanagedType.U1)] bool issued,
        [MarshalAs(UnmanagedType.U1)] bool revoked,
        string tailsPath,
        out int statusList
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_update_revocation_status_list(
        int statusList,
        string issuedJson,
        string revokedJson,
        string timestamp,
        out int updatedList,
        out int delta
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_create_revocation_state(
        AnoncredsCredentialRevocationInfo credRevInfo,
        int revRegDef,
        int statusList,
        string timestamp,
        string tailsPath,
        out int revState
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_update_revocation_state(
        int revState,
        int revRegDef,
        int statusListDelta,
        string timestamp,
        string tailsPath,
        out int updatedState
    );
}
