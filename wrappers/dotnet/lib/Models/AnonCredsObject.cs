using System.Runtime.InteropServices;
using AnonCredsNet.Exceptions;
using AnonCredsNet.Interop;
using AnonCredsNet.Requests;

namespace AnonCredsNet.Models;

public abstract class AnonCredsObject : IDisposable
{
    public long Handle { get; private set; }

    protected AnonCredsObject(long handle)
    {
        if (handle == 0)
            throw new AnonCredsException(ErrorCode.CommonInvalidState, "Invalid native handle");
        Handle = handle;
    }

    public string ToJson()
    {
        if (Handle == 0)
            throw new ObjectDisposedException(GetType().Name);
        var code = NativeMethods.anoncreds_object_get_json(Handle, out var buffer);
        if (code != ErrorCode.Success)
        {
            var errorMsg = AnonCreds.GetCurrentError();
            throw new AnonCredsException(code, $"ToJson failed for {GetType().Name}: {errorMsg}");
        }
        try
        {
            var json =
                Marshal.PtrToStringUTF8(buffer.Data, checked((int)buffer.Len))
                ?? throw new InvalidOperationException("Null JSON");
            return json;
        }
        finally
        {
            NativeMethods.anoncreds_buffer_free(buffer);
        }
    }

    protected static T FromJson<T>(string json)
        where T : AnonCredsObject
    {
        if (string.IsNullOrEmpty(json))
            throw new ArgumentNullException(nameof(json));

        var code = FromJsonInternal(typeof(T), json, out var handle);
        if (code != ErrorCode.Success)
            throw new AnonCredsException(code, AnonCreds.GetCurrentError());
        return (T)
            Activator.CreateInstance(
                typeof(T),
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance,
                null,
                [handle],
                null
            )!;
    }

    private static ErrorCode FromJsonInternal(Type type, string json, out long handle)
    {
        handle = 0;
        var buffer = AnonCreds.CreateByteBuffer(json);

        try
        {
            if (type == typeof(Schema))
                return NativeMethods.anoncreds_schema_from_json(buffer, out handle);
            else if (type == typeof(CredentialDefinition))
                return NativeMethods.anoncreds_credential_definition_from_json(buffer, out handle);
            else if (type == typeof(CredentialDefinitionPrivate))
                return NativeMethods.anoncreds_credential_definition_private_from_json(
                    buffer,
                    out handle
                );
            else if (type == typeof(KeyCorrectnessProof))
                return NativeMethods.anoncreds_key_correctness_proof_from_json(buffer, out handle);
            else if (type == typeof(CredentialOffer))
                return NativeMethods.anoncreds_credential_offer_from_json(buffer, out handle);
            else if (type == typeof(CredentialRequest))
                return NativeMethods.anoncreds_credential_request_from_json(buffer, out handle);
            else if (type == typeof(CredentialRequestMetadata))
                return NativeMethods.anoncreds_credential_request_metadata_from_json(
                    buffer,
                    out handle
                );
            else if (type == typeof(Credential))
                return NativeMethods.anoncreds_credential_from_json(buffer, out handle);
            else if (type == typeof(Presentation))
                return NativeMethods.anoncreds_presentation_from_json(buffer, out handle);
            else if (type == typeof(PresentationRequest))
                return NativeMethods.anoncreds_presentation_request_from_json(buffer, out handle);
            else if (type == typeof(RevocationRegistryDefinition))
                return NativeMethods.anoncreds_revocation_registry_definition_from_json(
                    buffer,
                    out handle
                );
            else if (type == typeof(RevocationRegistryDefinitionPrivate))
                return NativeMethods.anoncreds_revocation_registry_private_from_json(
                    buffer,
                    out handle
                );
            else if (type == typeof(RevocationStatusList))
                return NativeMethods.anoncreds_revocation_status_list_from_json(buffer, out handle);
            else if (type == typeof(RevocationStatusListDelta))
                return NativeMethods.anoncreds_revocation_status_list_delta_from_json(
                    buffer,
                    out handle
                );
            else if (type == typeof(RevocationState))
                return NativeMethods.anoncreds_revocation_state_from_json(buffer, out handle);
            else
                throw new NotSupportedException(
                    $"Type {type.Name} is not supported for JSON deserialization"
                );
        }
        finally
        {
            AnonCreds.FreeByteBuffer(buffer);
        }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (Handle == 0)
            return;
        NativeMethods.anoncreds_object_free(Handle);
        Handle = 0;
    }

    ~AnonCredsObject() => Dispose(false);
}
