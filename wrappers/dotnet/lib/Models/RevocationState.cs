using AnonCredsNet.Exceptions;
using AnonCredsNet.Interop;

namespace AnonCredsNet.Models;

public class RevocationState : AnonCredsObject
{
    private RevocationState(long handle)
        : base(handle) { }

    public static RevocationState Create(
        RevocationRegistryDefinition revRegDef,
        RevocationStatusList statusList,
        uint revRegIndex,
        string tailsPath
    )
    {
        if (revRegDef == null || statusList == null || string.IsNullOrEmpty(tailsPath))
            throw new ArgumentNullException("Input parameters cannot be null or empty");

        var code = NativeMethods.anoncreds_create_or_update_revocation_state(
            revRegDef.Handle,
            statusList.Handle,
            (long)revRegIndex,
            tailsPath,
            0,
            0,
            out var handle
        );
        if (code != ErrorCode.Success)
            throw new AnonCredsException(code, AnonCreds.GetCurrentError());
        return new RevocationState(handle);
    }

    public static RevocationState Update(
        RevocationState revState,
        RevocationRegistryDefinition revRegDef,
        RevocationStatusList newStatusList,
        uint revRegIndex,
        string tailsPath,
        RevocationStatusList? oldStatusList = null
    )
    {
        if (
            revState == null
            || revRegDef == null
            || newStatusList == null
            || string.IsNullOrEmpty(tailsPath)
        )
            throw new ArgumentNullException("Input parameters cannot be null or empty");
        var code = NativeMethods.anoncreds_create_or_update_revocation_state(
            revRegDef.Handle,
            newStatusList.Handle,
            (long)revRegIndex,
            tailsPath,
            revState.Handle,
            oldStatusList?.Handle ?? 0,
            out var updated
        );
        if (code != ErrorCode.Success)
            throw new AnonCredsException(code, AnonCreds.GetCurrentError());
        return new RevocationState(updated);
    }

    public static RevocationState FromJson(string json) => FromJson<RevocationState>(json);
}
