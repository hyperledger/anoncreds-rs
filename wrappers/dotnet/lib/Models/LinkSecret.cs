using System.Runtime.InteropServices;
using AnonCredsNet.Exceptions;
using AnonCredsNet.Interop;

namespace AnonCredsNet.Models;

public class LinkSecret : AnonCredsObject
{
    internal LinkSecret(long handle)
        : base(handle) { }

    public string Value => ToJson();

    public static string Create()
    {
        var code = NativeMethods.anoncreds_create_link_secret(out var ptr);
        if (code != ErrorCode.Success)
        {
            throw new AnonCredsException(code, AnonCreds.GetCurrentError());
        }
        var linkSecret =
            Marshal.PtrToStringUTF8(ptr) ?? throw new InvalidOperationException("Null link secret");
        NativeMethods.anoncreds_string_free(ptr);
        return linkSecret;
    }
}
