namespace AnonCredsNet.Objects;

public class KeyCorrectnessProof : AnonCredsObject
{
    internal KeyCorrectnessProof(int handle)
        : base(handle) { }

    internal static KeyCorrectnessProof FromJson(string json) =>
        FromJson<KeyCorrectnessProof>(json);
}
