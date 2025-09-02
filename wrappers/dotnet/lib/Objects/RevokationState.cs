using AnonCredsNet.Exceptions;
using AnonCredsNet.Helpers;
using AnonCredsNet.Interop;

namespace AnonCredsNet.Objects;

public class RevocationState : AnonCredsObject
{
    private RevocationState(int handle)
        : base(handle) { }

    public static RevocationState Create(
        int credRevInfo,
        RevocationRegistryDefinition revRegDef,
        RevocationStatusList statusList,
        string timestamp,
        string tailsPath
    )
    {
        if (
            credRevInfo == 0
            || revRegDef == null
            || statusList == null
            || string.IsNullOrEmpty(timestamp)
            || string.IsNullOrEmpty(tailsPath)
        )
            throw new ArgumentNullException("Input parameters cannot be null or empty");
        var code = NativeMethods.anoncreds_create_revocation_state(
            credRevInfo,
            revRegDef.Handle,
            statusList.Handle,
            timestamp,
            tailsPath,
            out var handle
        );
        if (code != ErrorCode.Success)
            throw new AnonCredsException(code, AnonCredsHelpers.GetCurrentError());
        return new RevocationState(handle);
    }

    public static RevocationState Update(
        RevocationState revState,
        RevocationRegistryDefinition revRegDef,
        RevocationStatusListDelta delta,
        string timestamp,
        string tailsPath
    )
    {
        if (
            revState == null
            || revRegDef == null
            || delta == null
            || string.IsNullOrEmpty(timestamp)
            || string.IsNullOrEmpty(tailsPath)
        )
            throw new ArgumentNullException("Input parameters cannot be null or empty");
        var code = NativeMethods.anoncreds_update_revocation_state(
            revState.Handle,
            revRegDef.Handle,
            delta.Handle,
            timestamp,
            tailsPath,
            out var updated
        );
        if (code != ErrorCode.Success)
            throw new AnonCredsException(code, AnonCredsHelpers.GetCurrentError());
        return new RevocationState(updated);
    }

    public static RevocationState FromJson(string json) => FromJson<RevocationState>(json);
}
