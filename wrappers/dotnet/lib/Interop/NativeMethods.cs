// NativeMethods.cs
using System.Runtime.InteropServices;

namespace AnonCredsNet.Interop;

internal static partial class NativeMethods
{
    private const string Library = "anoncreds";

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_get_current_error(out IntPtr errorJson);

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_create_link_secret(out IntPtr linkSecret);

    [LibraryImport(Library)]
    internal static partial void anoncreds_string_free(IntPtr str);

    [LibraryImport(Library)]
    internal static partial void anoncreds_buffer_free(ByteBuffer buf);

    [LibraryImport(Library)]
    internal static partial void anoncreds_object_free(long handle);

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_object_get_json(long handle, out ByteBuffer json);

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_object_from_json(string json, out long handle);

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_schema_from_json(ByteBuffer json, out long handle);

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_credential_definition_from_json(
        ByteBuffer json,
        out long handle
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_credential_definition_private_from_json(
        ByteBuffer json,
        out long handle
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_key_correctness_proof_from_json(
        ByteBuffer json,
        out long handle
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_credential_offer_from_json(
        ByteBuffer json,
        out long handle
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_credential_request_from_json(
        ByteBuffer json,
        out long handle
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_credential_request_metadata_from_json(
        ByteBuffer json,
        out long handle
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_credential_from_json(
        ByteBuffer json,
        out long handle
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_presentation_from_json(
        ByteBuffer json,
        out long handle
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_w3c_presentation_from_json(
        ByteBuffer json,
        out long handle
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_presentation_request_from_json(
        ByteBuffer json,
        out long handle
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_revocation_registry_definition_from_json(
        ByteBuffer json,
        out long handle
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_revocation_registry_private_from_json(
        ByteBuffer json,
        out long handle
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_revocation_status_list_from_json(
        ByteBuffer json,
        out long handle
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_revocation_status_list_delta_from_json(
        ByteBuffer json,
        out long handle
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_revocation_state_from_json(
        ByteBuffer json,
        out long handle
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_w3c_credential_from_json(
        ByteBuffer json,
        out long handle
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_generate_nonce(out IntPtr nonce);

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_create_schema(
        string name,
        string version,
        string issuerId,
        FfiStrList attrNames,
        out long handle
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_create_credential_definition(
        string schemaId,
        long schema,
        string tag,
        string issuerId,
        string signatureType,
        [MarshalAs(UnmanagedType.I1)] bool supportRevocation,
        out long credDef,
        out long credDefPvt,
        out long keyProof
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_create_credential_offer(
        string schemaId,
        string credDefId,
        long keyProof,
        out long offer
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_create_credential_request(
        string? entropy,
        string? proverDid,
        long credDef,
        string linkSecret,
        string linkSecretId,
        long credOffer,
        out long request,
        out long metadata
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_create_credential(
        long credDef,
        long credDefPvt,
        long credOffer,
        long credRequest,
        FfiStrList attrNames,
        FfiStrList attrRawValues,
        FfiStrList attrEncValues,
        IntPtr revocation,
        out long credential
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_process_credential(
        long credential,
        long requestMetadata,
        string linkSecret,
        long credDef,
        long revRegDef,
        out long processedCredential
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_create_presentation(
        long presReq,
        FfiCredentialEntryList credentials,
        FfiCredentialProveList credentialsProve,
        FfiStrList selfAttestNames,
        FfiStrList selfAttestValues,
        string linkSecret,
        FfiObjectHandleList schemas,
        FfiStrList schemaIds,
        FfiObjectHandleList credDefs,
        FfiStrList credDefIds,
        out long presentation
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_create_w3c_presentation(
        long presReq,
        FfiCredentialEntryList credentials,
        FfiCredentialProveList credentialsProve,
        string linkSecret,
        FfiObjectHandleList schemas,
        FfiStrList schemaIds,
        FfiObjectHandleList credDefs,
        FfiStrList credDefIds,
        string w3cVersion,
        out long presentation
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_verify_presentation(
        long presentation,
        long presReq,
        FfiObjectHandleList schemas,
        FfiStrList schemaIds,
        FfiObjectHandleList credDefs,
        FfiStrList credDefIds,
        FfiObjectHandleList revRegDefs,
        FfiStrList revRegDefIds,
        FfiObjectHandleList revStatusLists,
        FfiNonrevokedIntervalOverrideList nonrevokedIntervalOverride,
        out sbyte isValid
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_verify_w3c_presentation(
        long presentation,
        long presReq,
        FfiObjectHandleList schemas,
        FfiStrList schemaIds,
        FfiObjectHandleList credDefs,
        FfiStrList credDefIds,
        FfiObjectHandleList revRegDefs,
        FfiStrList revRegDefIds,
        FfiObjectHandleList revStatusLists,
        FfiNonrevokedIntervalOverrideList nonrevokedIntervalOverride,
        out sbyte isValid
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_create_revocation_registry_def(
        long credDef,
        string credDefId,
        string issuerId,
        string tag,
        string revType,
        long maxCredNum,
        string tailsPath,
        out long revRegDef,
        out long revRegPvt
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_create_revocation_status_list(
        long credDef,
        string revRegDefId,
        long revRegDef,
        long revRegDefPrivate,
        string issuerId,
        [MarshalAs(UnmanagedType.I1)] bool issuanceByDefault,
        long timestamp,
        out long statusList
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_update_revocation_status_list(
        long credDef,
        long revRegDef,
        long revRegPriv,
        long currentStatusList,
        FfiInt32List issued,
        FfiInt32List revoked,
        long timestamp,
        out long newStatusList
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_create_or_update_revocation_state(
        long revRegDef,
        long revStatusList,
        long revRegIndex,
        string tailsPath,
        long revState,
        long oldRevStatusList,
        out long revStateOut
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_revocation_registry_definition_get_attribute(
        long handle,
        string name,
        out IntPtr value
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_create_w3c_credential(
        long credDef,
        long credDefPvt,
        long credOffer,
        long credRequest,
        FfiStrList attrNames,
        FfiStrList attrRawValues,
        IntPtr revocation,
        string w3cVersion,
        out long credential
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_process_w3c_credential(
        long credential,
        long requestMetadata,
        string linkSecret,
        long credDef,
        long revRegDef,
        out long processedCredential
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_credential_from_w3c(
        long w3cCredential,
        out long legacyCredential
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_credential_to_w3c(
        long legacyCredential,
        string issuerId,
        string w3cVersion,
        out long w3cCredential
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_credential_get_attribute(
        long handle,
        string name,
        out IntPtr value
    );

    [LibraryImport(Library)]
    internal static partial ErrorCode anoncreds_w3c_credential_get_integrity_proof_details(
        long handle,
        out long proofInfoHandle
    );

    [LibraryImport(Library, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ErrorCode anoncreds_w3c_credential_proof_get_attribute(
        long proofInfoHandle,
        string name,
        out IntPtr value
    );
}
