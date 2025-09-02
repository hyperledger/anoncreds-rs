using System.Runtime.InteropServices;
using AnonCredsNet.Exceptions;
using AnonCredsNet.Helpers;
using AnonCredsNet.Interop;

namespace AnonCredsNet.Objects;

public abstract class AnonCredsObject : IDisposable
{
    internal int Handle { get; private set; }

    protected AnonCredsObject(int handle)
    {
        if (handle == 0)
            throw new AnonCredsException(ErrorCode.CommonInvalidState, "Invalid native handle");
        Handle = handle;
    }

    public string ToJson()
    {
        if (Handle == 0)
            throw new ObjectDisposedException(GetType().Name);
        var code = NativeMethods.anoncreds_object_get_json(Handle, out var ptr);
        if (code != ErrorCode.Success)
            throw new AnonCredsException(code, AnonCredsHelpers.GetCurrentError());
        var json = Marshal.PtrToStringUTF8(ptr) ?? throw new InvalidOperationException("Null JSON");
        NativeMethods.anoncreds_string_free(ptr);
        return json;
    }

    protected static T FromJson<T>(string json)
        where T : AnonCredsObject
    {
        if (string.IsNullOrEmpty(json))
            throw new ArgumentNullException(nameof(json));
        var code = NativeMethods.anoncreds_object_from_json(json, out var handle);
        if (code != ErrorCode.Success)
            throw new AnonCredsException(code, AnonCredsHelpers.GetCurrentError());
        return (T)Activator.CreateInstance(typeof(T), handle)!;
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
