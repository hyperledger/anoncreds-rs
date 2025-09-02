using AnonCredsNet.Objects;

namespace AnonCredsNet.Requests;

public class CredentialRequestMetadata : AnonCredsObject
{
    internal CredentialRequestMetadata(int handle)
        : base(handle) { }

    internal static CredentialRequestMetadata FromJson(string json) =>
        FromJson<CredentialRequestMetadata>(json);
}
