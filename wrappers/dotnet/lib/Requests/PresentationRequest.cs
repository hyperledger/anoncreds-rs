using AnonCredsNet.Models;

namespace AnonCredsNet.Requests;

public sealed class PresentationRequest : AnonCredsObject
{
    internal PresentationRequest(long handle)
        : base(handle) { }

    public static PresentationRequest FromJson(string json) =>
        AnonCredsObject.FromJson<PresentationRequest>(json);
}
