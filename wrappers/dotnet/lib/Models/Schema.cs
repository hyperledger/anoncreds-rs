using AnonCredsNet.Exceptions;
using AnonCredsNet.Interop;

namespace AnonCredsNet.Models;

public class Schema : AnonCredsObject
{
    private Schema(long handle)
        : base(handle) { }

    public static Schema Create(string name, string version, string issuerId, string attrNamesJson)
    {
        var attrNamesList = AnonCreds.CreateFfiStrList(attrNamesJson);
        try
        {
            var code = NativeMethods.anoncreds_create_schema(
                name,
                version,
                issuerId,
                attrNamesList,
                out var handle
            );
            if (code != ErrorCode.Success)
                throw new AnonCredsException(code, AnonCreds.GetCurrentError());
            return new Schema(handle);
        }
        finally
        {
            AnonCreds.FreeFfiStrList(attrNamesList);
        }
    }

    public static Schema FromJson(string json) => FromJson<Schema>(json);
}
