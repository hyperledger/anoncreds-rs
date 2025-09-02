using AnonCredsNet.Exceptions;
using AnonCredsNet.Helpers;
using AnonCredsNet.Interop;

namespace AnonCredsNet.Objects;

public class Schema : AnonCredsObject
{
    private Schema(int handle)
        : base(handle) { }

    internal static Schema Create(
        string issuerId,
        string name,
        string version,
        string attrNamesJson
    )
    {
        var code = NativeMethods.anoncreds_create_schema(
            issuerId,
            name,
            version,
            attrNamesJson,
            out var handle
        );
        if (code != ErrorCode.Success)
            throw new AnonCredsException(code, AnonCredsHelpers.GetCurrentError());
        return new Schema(handle);
    }

    internal static Schema FromJson(string json) => FromJson<Schema>(json);
}
