using AnonCredsNet.Interop;

namespace AnonCredsNet.Exceptions;

public class AnonCredsException : Exception
{
    public ErrorCode Code { get; }

    public AnonCredsException(ErrorCode code, string message)
        : base(message) => Code = code;
}
