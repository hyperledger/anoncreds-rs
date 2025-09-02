using AnonCredsNet.Exceptions;
using AnonCredsNet.Helpers;
using AnonCredsNet.Interop;

namespace AnonCredsNet.Objects;

public class RevocationStatusList : AnonCredsObject
{
    private RevocationStatusList(int handle)
        : base(handle) { }

    public static (
        RevocationRegistryDefinition RevRegDef,
        RevocationRegistryPrivate RevRegPvt,
        RevocationStatusList StatusList
    ) CreateRevocationRegistryDefinition(
        CredentialDefinition credDef,
        string issuerId,
        string tag,
        string revType,
        string config,
        string tailsPath
    )
    {
        if (
            credDef == null
            || string.IsNullOrEmpty(issuerId)
            || string.IsNullOrEmpty(tag)
            || string.IsNullOrEmpty(revType)
            || string.IsNullOrEmpty(config)
            || string.IsNullOrEmpty(tailsPath)
        )
            throw new ArgumentNullException("Input parameters cannot be null or empty");
        var code = NativeMethods.anoncreds_create_revocation_registry_def(
            credDef.Handle,
            issuerId,
            tag,
            revType,
            config,
            tailsPath,
            out var def,
            out var pvt,
            out var list
        );
        if (code != ErrorCode.Success)
            throw new AnonCredsException(code, AnonCredsHelpers.GetCurrentError());
        return (
            new RevocationRegistryDefinition(def),
            new RevocationRegistryPrivate(pvt),
            new RevocationStatusList(list)
        );
    }

    public static RevocationStatusList Create(
        string issuerId,
        RevocationRegistryDefinition revRegDef,
        string timestamp,
        bool issued,
        bool revoked,
        string tailsPath
    )
    {
        if (
            string.IsNullOrEmpty(issuerId)
            || revRegDef == null
            || string.IsNullOrEmpty(timestamp)
            || string.IsNullOrEmpty(tailsPath)
        )
            throw new ArgumentNullException("Input parameters cannot be null or empty");
        var code = NativeMethods.anoncreds_create_revocation_status_list(
            issuerId,
            revRegDef.Handle,
            timestamp,
            issued,
            revoked,
            tailsPath,
            out var handle
        );
        if (code != ErrorCode.Success)
            throw new AnonCredsException(code, AnonCredsHelpers.GetCurrentError());
        return new RevocationStatusList(handle);
    }

    public static (RevocationStatusList UpdatedList, RevocationStatusListDelta Delta) Update(
        RevocationStatusList statusList,
        string? issuedJson,
        string? revokedJson,
        string timestamp
    )
    {
        if (statusList == null || string.IsNullOrEmpty(timestamp))
            throw new ArgumentNullException("Input parameters cannot be null or empty");
        var code = NativeMethods.anoncreds_update_revocation_status_list(
            statusList.Handle,
            issuedJson ?? "{}",
            revokedJson ?? "{}",
            timestamp,
            out var updated,
            out var delta
        );
        if (code != ErrorCode.Success)
            throw new AnonCredsException(code, AnonCredsHelpers.GetCurrentError());
        return (new RevocationStatusList(updated), new RevocationStatusListDelta(delta));
    }

    public static RevocationStatusList FromJson(string json) =>
        FromJson<RevocationStatusList>(json);
}
