namespace AnonCredsNet.Models;

public class RevocationRegistryDefinitionPrivate : AnonCredsObject
{
    internal RevocationRegistryDefinitionPrivate(long handle)
        : base(handle) { }

    public static RevocationRegistryDefinitionPrivate FromJson(string json) =>
        FromJson<RevocationRegistryDefinitionPrivate>(json);
}
