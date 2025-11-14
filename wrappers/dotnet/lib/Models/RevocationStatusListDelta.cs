namespace AnonCredsNet.Models;

public class RevocationStatusListDelta : AnonCredsObject
{
    internal RevocationStatusListDelta(long handle)
        : base(handle) { }

    public static RevocationStatusListDelta FromJson(string json) =>
        FromJson<RevocationStatusListDelta>(json);
}
