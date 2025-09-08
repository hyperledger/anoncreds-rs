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
public struct ObjectHandle
{
    // Match C typedef i64 ObjectHandle;
    public long Value;
}

[StructLayout(LayoutKind.Sequential)]
internal struct ByteBuffer
{
    // C layout: int64_t len; uint8_t* data;
    public long Len;
    public IntPtr Data;
}

[StructLayout(LayoutKind.Sequential)]
public struct FfiList
{
    // C layout: size_t count; const T* data;
    public UIntPtr Count; // usize is unsigned pointer-sized
    public IntPtr Data; // Pointer to array of elements (blittable)
}

[StructLayout(LayoutKind.Sequential)]
public struct FfiStrList
{
    public UIntPtr Count; // usize is unsigned pointer-sized
    public IntPtr Data; // POINTER(c_char_p)
}

// Added structs to align with anoncreds-rs FFI
[StructLayout(LayoutKind.Sequential)]
internal struct AnoncredsPresentationRequest
{
    public IntPtr Json; // Pointer to JSON string
}

[StructLayout(LayoutKind.Sequential)]
internal struct FfiCredentialEntry
{
    // C layout uses ObjectHandle (i64), i32 timestamp, ObjectHandle
    public long Credential;
    public int Timestamp;
    public long RevState;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FfiCredentialProve
{
    public long EntryIdx;
    public IntPtr Referent; // FfiStr
    public byte IsPredicate;
    public byte Reveal;
}

[StructLayout(LayoutKind.Sequential)]
public struct FfiCredentialEntryList
{
    public UIntPtr Count; // usize is unsigned pointer-sized
    public IntPtr Data; // POINTER(FfiCredentialEntry)
}

[StructLayout(LayoutKind.Sequential)]
public struct FfiCredentialProveList
{
    public UIntPtr Count; // usize is unsigned pointer-sized
    public IntPtr Data; // POINTER(FfiCredentialProve)
}

[StructLayout(LayoutKind.Sequential)]
public struct FfiObjectHandleList
{
    public UIntPtr Count; // usize is unsigned pointer-sized
    public IntPtr Data; // POINTER(ObjectHandle)
}

// List of 32-bit integers used in revocation status list updates
[StructLayout(LayoutKind.Sequential)]
public struct FfiInt32List
{
    public UIntPtr Count; // size_t
    public IntPtr Data; // pointer to int32_t
}

// Revocation configuration struct passed to create_credential
[StructLayout(LayoutKind.Sequential)]
public struct FfiCredRevInfo
{
    public long RegDef; // ObjectHandle (size_t)
    public long RegDefPrivate; // ObjectHandle (size_t)
    public long StatusList; // ObjectHandle (size_t)
    public long RegIdx; // int64_t
}

// Non-revoked interval override types required by verify_presentation
[StructLayout(LayoutKind.Sequential)]
public struct FfiNonrevokedIntervalOverride
{
    public IntPtr RevRegDefId; // FfiStr (char*)
    public int RequestedFromTs; // i32
    public int OverrideRevStatusListTs; // i32
}

[StructLayout(LayoutKind.Sequential)]
public struct FfiNonrevokedIntervalOverrideList
{
    public UIntPtr Count; // usize is unsigned pointer-sized
    public IntPtr Data; // pointer to FfiNonrevokedIntervalOverride
}
