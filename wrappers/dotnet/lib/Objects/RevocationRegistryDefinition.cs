namespace AnonCredsNet.Objects;

public class RevocationRegistryDefinition : AnonCredsObject
{
    internal RevocationRegistryDefinition(int handle)
        : base(handle) { }

    public static RevocationRegistryDefinition FromJson(string json) =>
        FromJson<RevocationRegistryDefinition>(json);
}
