using AnonCredsNet.Models;

namespace AnonCredsNet.Requests;

public class CredentialRequestMetadata : AnonCredsObject
{
    internal CredentialRequestMetadata(long handle)
        : base(handle) { }

    internal static CredentialRequestMetadata FromJson(string json) =>
        FromJson<CredentialRequestMetadata>(json);
}
