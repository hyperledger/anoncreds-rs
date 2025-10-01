namespace AnonCredsNet.Models;

public class CredentialRevocationConfig
{
    public RevocationRegistryDefinition? RevRegDef { get; set; }
    public RevocationRegistryDefinitionPrivate? RevRegDefPrivate { get; set; }
    public RevocationStatusList? RevStatusList { get; set; }
    public uint RevRegIndex { get; set; }
}
