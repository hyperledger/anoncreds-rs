namespace AnonCredsNet.Models;

public class KeyCorrectnessProof : AnonCredsObject
{
    internal KeyCorrectnessProof(long handle)
        : base(handle) { }

    internal static KeyCorrectnessProof FromJson(string json) =>
        FromJson<KeyCorrectnessProof>(json);
}
