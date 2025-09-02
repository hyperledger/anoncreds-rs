// InteropTypes.cs
using System.Runtime.InteropServices;

namespace AnonCredsNet.Interop;

public enum ErrorCode : int
{
    Success = 0,
    CommonInvalidParam1 = 100,
    CommonInvalidParam2 = 101,
    CommonInvalidParam3 = 102,
    CommonInvalidParam4 = 103,
    CommonInvalidParam5 = 104,
    CommonInvalidParam6 = 105,
    CommonInvalidParam7 = 106,
    CommonInvalidParam8 = 107,
    CommonInvalidParam9 = 108,
    CommonInvalidParam10 = 109,
    CommonInvalidParam11 = 110,
    CommonInvalidParam12 = 111,
    CommonInvalidState = 112,
    CommonInvalidStructure = 113,
    CommonIOError = 114,
    AnoncredsRevocationAccumulatorIsFull = 115,
    AnoncredsInvalidRevocationAccumulatorIndex = 116,
    AnoncredsCredentialRevoked = 117,
    AnoncredsProofRejected = 118,
    AnoncredsInvalidUserRevocId = 119,
    // Add more if needed from error.rs
}

[StructLayout(LayoutKind.Sequential)]
internal struct ObjectHandle
{
    public int Value { get; }

    public ObjectHandle(int value) => Value = value;

    public static implicit operator int(ObjectHandle h) => h.Value;

    public static implicit operator ObjectHandle(int v) => new(v);
}

[StructLayout(LayoutKind.Sequential)]
internal struct ByteBuffer
{
    public int Len;
    public IntPtr Data;
}

[StructLayout(LayoutKind.Sequential)]
public struct FfiList
{
    public IntPtr Handles; // Pointer to array of handles
    public int Count;
}

// Added structs to align with anoncreds-rs FFI
[StructLayout(LayoutKind.Sequential)]
internal struct AnoncredsPresentationRequest
{
    public IntPtr Json; // Pointer to JSON string
}

[StructLayout(LayoutKind.Sequential)]
internal struct AnoncredsCredentialRevocationInfo
{
    public IntPtr Json; // Pointer to JSON string
}
