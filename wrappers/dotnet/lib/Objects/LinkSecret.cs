using AnonCredsNet.Exceptions;
using AnonCredsNet.Helpers;
using AnonCredsNet.Interop;

namespace AnonCredsNet.Objects;

public sealed class LinkSecret : AnonCredsObject
{
    private LinkSecret(int handle)
        : base(handle) { }

    internal static LinkSecret Create()
    {
        var code = NativeMethods.anoncreds_create_link_secret(out var handle);
        if (code != ErrorCode.Success)
            throw new AnonCredsException(code, AnonCredsHelpers.GetCurrentError());
        return new LinkSecret(handle);
    }

    internal static LinkSecret FromJson(string json) => FromJson<LinkSecret>(json);
}
