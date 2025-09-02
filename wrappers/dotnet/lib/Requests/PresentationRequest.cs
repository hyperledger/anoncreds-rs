using AnonCredsNet.Objects;

namespace AnonCredsNet.Requests;

public sealed class PresentationRequest : AnonCredsObject
{
    internal PresentationRequest(int handle)
        : base(handle) { }

    internal static PresentationRequest FromJson(string json) =>
        FromJson<PresentationRequest>(json);
}
