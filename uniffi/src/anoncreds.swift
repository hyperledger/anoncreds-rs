// This file was autogenerated by some hot garbage in the `uniffi` crate.
// Trust me, you don't want to mess with it!
import Foundation

// Depending on the consumer's build setup, the low-level FFI code
// might be in a separate module, or it might be compiled inline into
// this module. This is a bit of light hackery to work with both.
#if canImport(anoncredsFFI)
    import anoncredsFFI
#endif

private extension RustBuffer {
    // Allocate a new buffer, copying the contents of a `UInt8` array.
    init(bytes: [UInt8]) {
        let rbuf = bytes.withUnsafeBufferPointer { ptr in
            RustBuffer.from(ptr)
        }
        self.init(capacity: rbuf.capacity, len: rbuf.len, data: rbuf.data)
    }

    static func from(_ ptr: UnsafeBufferPointer<UInt8>) -> RustBuffer {
        try! rustCall { ffi_anoncreds_200b_rustbuffer_from_bytes(ForeignBytes(bufferPointer: ptr), $0) }
    }

    // Frees the buffer in place.
    // The buffer must not be used after this is called.
    func deallocate() {
        try! rustCall { ffi_anoncreds_200b_rustbuffer_free(self, $0) }
    }
}

private extension ForeignBytes {
    init(bufferPointer: UnsafeBufferPointer<UInt8>) {
        self.init(len: Int32(bufferPointer.count), data: bufferPointer.baseAddress)
    }
}

// For every type used in the interface, we provide helper methods for conveniently
// lifting and lowering that type from C-compatible data, and for reading and writing
// values of that type in a buffer.

// Helper classes/extensions that don't change.
// Someday, this will be in a library of its own.

private extension Data {
    init(rustBuffer: RustBuffer) {
        // TODO: This copies the buffer. Can we read directly from a
        // Rust buffer?
        self.init(bytes: rustBuffer.data!, count: Int(rustBuffer.len))
    }
}

// Define reader functionality.  Normally this would be defined in a class or
// struct, but we use standalone functions instead in order to make external
// types work.
//
// With external types, one swift source file needs to be able to call the read
// method on another source file's FfiConverter, but then what visibility
// should Reader have?
// - If Reader is fileprivate, then this means the read() must also
//   be fileprivate, which doesn't work with external types.
// - If Reader is internal/public, we'll get compile errors since both source
//   files will try define the same type.
//
// Instead, the read() method and these helper functions input a tuple of data

private func createReader(data: Data) -> (data: Data, offset: Data.Index) {
    (data: data, offset: 0)
}

// Reads an integer at the current offset, in big-endian order, and advances
// the offset on success. Throws if reading the integer would move the
// offset past the end of the buffer.
private func readInt<T: FixedWidthInteger>(_ reader: inout (data: Data, offset: Data.Index)) throws -> T {
    let range = reader.offset ..< reader.offset + MemoryLayout<T>.size
    guard reader.data.count >= range.upperBound else {
        throw UniffiInternalError.bufferOverflow
    }
    if T.self == UInt8.self {
        let value = reader.data[reader.offset]
        reader.offset += 1
        return value as! T
    }
    var value: T = 0
    let _ = withUnsafeMutableBytes(of: &value) { reader.data.copyBytes(to: $0, from: range) }
    reader.offset = range.upperBound
    return value.bigEndian
}

// Reads an arbitrary number of bytes, to be used to read
// raw bytes, this is useful when lifting strings
private func readBytes(_ reader: inout (data: Data, offset: Data.Index), count: Int) throws -> [UInt8] {
    let range = reader.offset ..< (reader.offset + count)
    guard reader.data.count >= range.upperBound else {
        throw UniffiInternalError.bufferOverflow
    }
    var value = [UInt8](repeating: 0, count: count)
    value.withUnsafeMutableBufferPointer { buffer in
        reader.data.copyBytes(to: buffer, from: range)
    }
    reader.offset = range.upperBound
    return value
}

// Reads a float at the current offset.
private func readFloat(_ reader: inout (data: Data, offset: Data.Index)) throws -> Float {
    return Float(bitPattern: try readInt(&reader))
}

// Reads a float at the current offset.
private func readDouble(_ reader: inout (data: Data, offset: Data.Index)) throws -> Double {
    return Double(bitPattern: try readInt(&reader))
}

// Indicates if the offset has reached the end of the buffer.
private func hasRemaining(_ reader: (data: Data, offset: Data.Index)) -> Bool {
    return reader.offset < reader.data.count
}

// Define writer functionality.  Normally this would be defined in a class or
// struct, but we use standalone functions instead in order to make external
// types work.  See the above discussion on Readers for details.

private func createWriter() -> [UInt8] {
    return []
}

private func writeBytes<S>(_ writer: inout [UInt8], _ byteArr: S) where S: Sequence, S.Element == UInt8 {
    writer.append(contentsOf: byteArr)
}

// Writes an integer in big-endian order.
//
// Warning: make sure what you are trying to write
// is in the correct type!
private func writeInt<T: FixedWidthInteger>(_ writer: inout [UInt8], _ value: T) {
    var value = value.bigEndian
    withUnsafeBytes(of: &value) { writer.append(contentsOf: $0) }
}

private func writeFloat(_ writer: inout [UInt8], _ value: Float) {
    writeInt(&writer, value.bitPattern)
}

private func writeDouble(_ writer: inout [UInt8], _ value: Double) {
    writeInt(&writer, value.bitPattern)
}

// Protocol for types that transfer other types across the FFI. This is
// analogous go the Rust trait of the same name.
private protocol FfiConverter {
    associatedtype FfiType
    associatedtype SwiftType

    static func lift(_ value: FfiType) throws -> SwiftType
    static func lower(_ value: SwiftType) -> FfiType
    static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> SwiftType
    static func write(_ value: SwiftType, into buf: inout [UInt8])
}

// Types conforming to `Primitive` pass themselves directly over the FFI.
private protocol FfiConverterPrimitive: FfiConverter where FfiType == SwiftType {}

extension FfiConverterPrimitive {
    public static func lift(_ value: FfiType) throws -> SwiftType {
        return value
    }

    public static func lower(_ value: SwiftType) -> FfiType {
        return value
    }
}

// Types conforming to `FfiConverterRustBuffer` lift and lower into a `RustBuffer`.
// Used for complex types where it's hard to write a custom lift/lower.
private protocol FfiConverterRustBuffer: FfiConverter where FfiType == RustBuffer {}

extension FfiConverterRustBuffer {
    public static func lift(_ buf: RustBuffer) throws -> SwiftType {
        var reader = createReader(data: Data(rustBuffer: buf))
        let value = try read(from: &reader)
        if hasRemaining(reader) {
            throw UniffiInternalError.incompleteData
        }
        buf.deallocate()
        return value
    }

    public static func lower(_ value: SwiftType) -> RustBuffer {
        var writer = createWriter()
        write(value, into: &writer)
        return RustBuffer(bytes: writer)
    }
}

// An error type for FFI errors. These errors occur at the UniFFI level, not
// the library level.
private enum UniffiInternalError: LocalizedError {
    case bufferOverflow
    case incompleteData
    case unexpectedOptionalTag
    case unexpectedEnumCase
    case unexpectedNullPointer
    case unexpectedRustCallStatusCode
    case unexpectedRustCallError
    case unexpectedStaleHandle
    case rustPanic(_ message: String)

    public var errorDescription: String? {
        switch self {
        case .bufferOverflow: return "Reading the requested value would read past the end of the buffer"
        case .incompleteData: return "The buffer still has data after lifting its containing value"
        case .unexpectedOptionalTag: return "Unexpected optional tag; should be 0 or 1"
        case .unexpectedEnumCase: return "Raw enum value doesn't match any cases"
        case .unexpectedNullPointer: return "Raw pointer value was null"
        case .unexpectedRustCallStatusCode: return "Unexpected RustCallStatus code"
        case .unexpectedRustCallError: return "CALL_ERROR but no errorClass specified"
        case .unexpectedStaleHandle: return "The object in the handle map has been dropped already"
        case let .rustPanic(message): return message
        }
    }
}

private let CALL_SUCCESS: Int8 = 0
private let CALL_ERROR: Int8 = 1
private let CALL_PANIC: Int8 = 2

private extension RustCallStatus {
    init() {
        self.init(
            code: CALL_SUCCESS,
            errorBuf: RustBuffer(
                capacity: 0,
                len: 0,
                data: nil
            )
        )
    }
}

private func rustCall<T>(_ callback: (UnsafeMutablePointer<RustCallStatus>) -> T) throws -> T {
    try makeRustCall(callback, errorHandler: {
        $0.deallocate()
        return UniffiInternalError.unexpectedRustCallError
    })
}

private func rustCallWithError<T, F: FfiConverter>
(_ errorFfiConverter: F.Type, _ callback: (UnsafeMutablePointer<RustCallStatus>) -> T) throws -> T
    where F.SwiftType: Error, F.FfiType == RustBuffer
{
    try makeRustCall(callback, errorHandler: { try errorFfiConverter.lift($0) })
}

private func makeRustCall<T>(_ callback: (UnsafeMutablePointer<RustCallStatus>) -> T, errorHandler: (RustBuffer) throws -> Error) throws -> T {
    var callStatus = RustCallStatus()
    let returnedVal = callback(&callStatus)
    switch callStatus.code {
    case CALL_SUCCESS:
        return returnedVal

    case CALL_ERROR:
        throw try errorHandler(callStatus.errorBuf)

    case CALL_PANIC:
        // When the rust code sees a panic, it tries to construct a RustBuffer
        // with the message.  But if that code panics, then it just sends back
        // an empty buffer.
        if callStatus.errorBuf.len > 0 {
            throw UniffiInternalError.rustPanic(try FfiConverterString.lift(callStatus.errorBuf))
        } else {
            callStatus.errorBuf.deallocate()
            throw UniffiInternalError.rustPanic("Rust panic")
        }

    default:
        throw UniffiInternalError.unexpectedRustCallStatusCode
    }
}

// Public interface members begin here.

private struct FfiConverterString: FfiConverter {
    typealias SwiftType = String
    typealias FfiType = RustBuffer

    public static func lift(_ value: RustBuffer) throws -> String {
        defer {
            value.deallocate()
        }
        if value.data == nil {
            return String()
        }
        let bytes = UnsafeBufferPointer<UInt8>(start: value.data!, count: Int(value.len))
        return String(bytes: bytes, encoding: String.Encoding.utf8)!
    }

    public static func lower(_ value: String) -> RustBuffer {
        return value.utf8CString.withUnsafeBufferPointer { ptr in
            // The swift string gives us int8_t, we want uint8_t.
            ptr.withMemoryRebound(to: UInt8.self) { ptr in
                // The swift string gives us a trailing null byte, we don't want it.
                let buf = UnsafeBufferPointer(rebasing: ptr.prefix(upTo: ptr.count - 1))
                return RustBuffer.from(buf)
            }
        }
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> String {
        let len: Int32 = try readInt(&buf)
        return String(bytes: try readBytes(&buf, count: Int(len)), encoding: String.Encoding.utf8)!
    }

    public static func write(_ value: String, into buf: inout [UInt8]) {
        let len = Int32(value.utf8.count)
        writeInt(&buf, len)
        writeBytes(&buf, value.utf8)
    }
}

public protocol NonceProtocol {}

public class Nonce: NonceProtocol {
    fileprivate let pointer: UnsafeMutableRawPointer

    // TODO: We'd like this to be `private` but for Swifty reasons,
    // we can't implement `FfiConverter` without making this `required` and we can't
    // make it `required` without making it `public`.
    required init(unsafeFromRawPointer pointer: UnsafeMutableRawPointer) {
        self.pointer = pointer
    }

    public convenience init() {
        self.init(unsafeFromRawPointer: try!

            rustCall {
                anoncreds_200b_Nonce_new($0)
            })
    }

    deinit {
        try! rustCall { ffi_anoncreds_200b_Nonce_object_free(pointer, $0) }
    }
}

public struct FfiConverterTypeNonce: FfiConverter {
    typealias FfiType = UnsafeMutableRawPointer
    typealias SwiftType = Nonce

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> Nonce {
        let v: UInt64 = try readInt(&buf)
        // The Rust code won't compile if a pointer won't fit in a UInt64.
        // We have to go via `UInt` because that's the thing that's the size of a pointer.
        let ptr = UnsafeMutableRawPointer(bitPattern: UInt(truncatingIfNeeded: v))
        if ptr == nil {
            throw UniffiInternalError.unexpectedNullPointer
        }
        return try lift(ptr!)
    }

    public static func write(_ value: Nonce, into buf: inout [UInt8]) {
        // This fiddling is because `Int` is the thing that's the same size as a pointer.
        // The Rust code won't compile if a pointer won't fit in a `UInt64`.
        writeInt(&buf, UInt64(bitPattern: Int64(Int(bitPattern: lower(value)))))
    }

    public static func lift(_ pointer: UnsafeMutableRawPointer) throws -> Nonce {
        return Nonce(unsafeFromRawPointer: pointer)
    }

    public static func lower(_ value: Nonce) -> UnsafeMutableRawPointer {
        return value.pointer
    }
}

public protocol ProverProtocol {
    func createCredentialRequest(entropy: String, proverDid: String, credDef: CredentialDefinition, linkSecret: SecretLink, linkSecretId: String, credentialOffer: CredentialOffer) -> String
}

public class Prover: ProverProtocol {
    fileprivate let pointer: UnsafeMutableRawPointer

    // TODO: We'd like this to be `private` but for Swifty reasons,
    // we can't implement `FfiConverter` without making this `required` and we can't
    // make it `required` without making it `public`.
    required init(unsafeFromRawPointer pointer: UnsafeMutableRawPointer) {
        self.pointer = pointer
    }

    public convenience init() {
        self.init(unsafeFromRawPointer: try!

            rustCall {
                anoncreds_200b_Prover_new($0)
            })
    }

    deinit {
        try! rustCall { ffi_anoncreds_200b_Prover_object_free(pointer, $0) }
    }

    public func createCredentialRequest(entropy: String, proverDid: String, credDef: CredentialDefinition, linkSecret: SecretLink, linkSecretId: String, credentialOffer: CredentialOffer) -> String {
        return try! FfiConverterString.lift(
            try!
                rustCall {
                    anoncreds_200b_Prover_create_credential_request(self.pointer,
                                                                    FfiConverterString.lower(entropy),
                                                                    FfiConverterString.lower(proverDid),
                                                                    FfiConverterTypeCredentialDefinition.lower(credDef),
                                                                    FfiConverterTypeSecretLink.lower(linkSecret),
                                                                    FfiConverterString.lower(linkSecretId),
                                                                    FfiConverterTypeCredentialOffer.lower(credentialOffer), $0)
                }
        )
    }
}

public struct FfiConverterTypeProver: FfiConverter {
    typealias FfiType = UnsafeMutableRawPointer
    typealias SwiftType = Prover

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> Prover {
        let v: UInt64 = try readInt(&buf)
        // The Rust code won't compile if a pointer won't fit in a UInt64.
        // We have to go via `UInt` because that's the thing that's the size of a pointer.
        let ptr = UnsafeMutableRawPointer(bitPattern: UInt(truncatingIfNeeded: v))
        if ptr == nil {
            throw UniffiInternalError.unexpectedNullPointer
        }
        return try lift(ptr!)
    }

    public static func write(_ value: Prover, into buf: inout [UInt8]) {
        // This fiddling is because `Int` is the thing that's the same size as a pointer.
        // The Rust code won't compile if a pointer won't fit in a `UInt64`.
        writeInt(&buf, UInt64(bitPattern: Int64(Int(bitPattern: lower(value)))))
    }

    public static func lift(_ pointer: UnsafeMutableRawPointer) throws -> Prover {
        return Prover(unsafeFromRawPointer: pointer)
    }

    public static func lower(_ value: Prover) -> UnsafeMutableRawPointer {
        return value.pointer
    }
}

public struct CreateCrendentialRequestResponse {
    public var request: String
    public var metadata: String

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(request: String, metadata: String) {
        self.request = request
        self.metadata = metadata
    }
}

extension CreateCrendentialRequestResponse: Equatable, Hashable {
    public static func == (lhs: CreateCrendentialRequestResponse, rhs: CreateCrendentialRequestResponse) -> Bool {
        if lhs.request != rhs.request {
            return false
        }
        if lhs.metadata != rhs.metadata {
            return false
        }
        return true
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(request)
        hasher.combine(metadata)
    }
}

public struct FfiConverterTypeCreateCrendentialRequestResponse: FfiConverterRustBuffer {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> CreateCrendentialRequestResponse {
        return try CreateCrendentialRequestResponse(
            request: FfiConverterString.read(from: &buf),
            metadata: FfiConverterString.read(from: &buf)
        )
    }

    public static func write(_ value: CreateCrendentialRequestResponse, into buf: inout [UInt8]) {
        FfiConverterString.write(value.request, into: &buf)
        FfiConverterString.write(value.metadata, into: &buf)
    }
}

public func FfiConverterTypeCreateCrendentialRequestResponse_lift(_ buf: RustBuffer) throws -> CreateCrendentialRequestResponse {
    return try FfiConverterTypeCreateCrendentialRequestResponse.lift(buf)
}

public func FfiConverterTypeCreateCrendentialRequestResponse_lower(_ value: CreateCrendentialRequestResponse) -> RustBuffer {
    return FfiConverterTypeCreateCrendentialRequestResponse.lower(value)
}

public struct CredentialDefinition {
    public var schemaId: SchemaId
    public var signatureType: SignatureType
    public var tag: String
    public var value: CredentialDefinitionData
    public var issuerId: IssuerId

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(schemaId: SchemaId, signatureType: SignatureType, tag: String, value: CredentialDefinitionData, issuerId: IssuerId) {
        self.schemaId = schemaId
        self.signatureType = signatureType
        self.tag = tag
        self.value = value
        self.issuerId = issuerId
    }
}

extension CredentialDefinition: Equatable, Hashable {
    public static func == (lhs: CredentialDefinition, rhs: CredentialDefinition) -> Bool {
        if lhs.schemaId != rhs.schemaId {
            return false
        }
        if lhs.signatureType != rhs.signatureType {
            return false
        }
        if lhs.tag != rhs.tag {
            return false
        }
        if lhs.value != rhs.value {
            return false
        }
        if lhs.issuerId != rhs.issuerId {
            return false
        }
        return true
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(schemaId)
        hasher.combine(signatureType)
        hasher.combine(tag)
        hasher.combine(value)
        hasher.combine(issuerId)
    }
}

public struct FfiConverterTypeCredentialDefinition: FfiConverterRustBuffer {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> CredentialDefinition {
        return try CredentialDefinition(
            schemaId: FfiConverterTypeSchemaId.read(from: &buf),
            signatureType: FfiConverterTypeSignatureType.read(from: &buf),
            tag: FfiConverterString.read(from: &buf),
            value: FfiConverterTypeCredentialDefinitionData.read(from: &buf),
            issuerId: FfiConverterTypeIssuerId.read(from: &buf)
        )
    }

    public static func write(_ value: CredentialDefinition, into buf: inout [UInt8]) {
        FfiConverterTypeSchemaId.write(value.schemaId, into: &buf)
        FfiConverterTypeSignatureType.write(value.signatureType, into: &buf)
        FfiConverterString.write(value.tag, into: &buf)
        FfiConverterTypeCredentialDefinitionData.write(value.value, into: &buf)
        FfiConverterTypeIssuerId.write(value.issuerId, into: &buf)
    }
}

public func FfiConverterTypeCredentialDefinition_lift(_ buf: RustBuffer) throws -> CredentialDefinition {
    return try FfiConverterTypeCredentialDefinition.lift(buf)
}

public func FfiConverterTypeCredentialDefinition_lower(_ value: CredentialDefinition) -> RustBuffer {
    return FfiConverterTypeCredentialDefinition.lower(value)
}

public struct CredentialDefinitionData {
    public var primary: String
    public var revocation: String?

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(primary: String, revocation: String?) {
        self.primary = primary
        self.revocation = revocation
    }
}

extension CredentialDefinitionData: Equatable, Hashable {
    public static func == (lhs: CredentialDefinitionData, rhs: CredentialDefinitionData) -> Bool {
        if lhs.primary != rhs.primary {
            return false
        }
        if lhs.revocation != rhs.revocation {
            return false
        }
        return true
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(primary)
        hasher.combine(revocation)
    }
}

public struct FfiConverterTypeCredentialDefinitionData: FfiConverterRustBuffer {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> CredentialDefinitionData {
        return try CredentialDefinitionData(
            primary: FfiConverterString.read(from: &buf),
            revocation: FfiConverterOptionString.read(from: &buf)
        )
    }

    public static func write(_ value: CredentialDefinitionData, into buf: inout [UInt8]) {
        FfiConverterString.write(value.primary, into: &buf)
        FfiConverterOptionString.write(value.revocation, into: &buf)
    }
}

public func FfiConverterTypeCredentialDefinitionData_lift(_ buf: RustBuffer) throws -> CredentialDefinitionData {
    return try FfiConverterTypeCredentialDefinitionData.lift(buf)
}

public func FfiConverterTypeCredentialDefinitionData_lower(_ value: CredentialDefinitionData) -> RustBuffer {
    return FfiConverterTypeCredentialDefinitionData.lower(value)
}

public struct CredentialDefinitionId {
    public var id: String

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(id: String) {
        self.id = id
    }
}

extension CredentialDefinitionId: Equatable, Hashable {
    public static func == (lhs: CredentialDefinitionId, rhs: CredentialDefinitionId) -> Bool {
        if lhs.id != rhs.id {
            return false
        }
        return true
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
}

public struct FfiConverterTypeCredentialDefinitionId: FfiConverterRustBuffer {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> CredentialDefinitionId {
        return try CredentialDefinitionId(
            id: FfiConverterString.read(from: &buf)
        )
    }

    public static func write(_ value: CredentialDefinitionId, into buf: inout [UInt8]) {
        FfiConverterString.write(value.id, into: &buf)
    }
}

public func FfiConverterTypeCredentialDefinitionId_lift(_ buf: RustBuffer) throws -> CredentialDefinitionId {
    return try FfiConverterTypeCredentialDefinitionId.lift(buf)
}

public func FfiConverterTypeCredentialDefinitionId_lower(_ value: CredentialDefinitionId) -> RustBuffer {
    return FfiConverterTypeCredentialDefinitionId.lower(value)
}

public struct CredentialOffer {
    public var schemaId: SchemaId
    public var credDefId: CredentialDefinitionId
    public var keyCorrectnessProof: String
    public var nonce: Nonce
    public var methodName: String?

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(schemaId: SchemaId, credDefId: CredentialDefinitionId, keyCorrectnessProof: String, nonce: Nonce, methodName: String?) {
        self.schemaId = schemaId
        self.credDefId = credDefId
        self.keyCorrectnessProof = keyCorrectnessProof
        self.nonce = nonce
        self.methodName = methodName
    }
}

public struct FfiConverterTypeCredentialOffer: FfiConverterRustBuffer {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> CredentialOffer {
        return try CredentialOffer(
            schemaId: FfiConverterTypeSchemaId.read(from: &buf),
            credDefId: FfiConverterTypeCredentialDefinitionId.read(from: &buf),
            keyCorrectnessProof: FfiConverterString.read(from: &buf),
            nonce: FfiConverterTypeNonce.read(from: &buf),
            methodName: FfiConverterOptionString.read(from: &buf)
        )
    }

    public static func write(_ value: CredentialOffer, into buf: inout [UInt8]) {
        FfiConverterTypeSchemaId.write(value.schemaId, into: &buf)
        FfiConverterTypeCredentialDefinitionId.write(value.credDefId, into: &buf)
        FfiConverterString.write(value.keyCorrectnessProof, into: &buf)
        FfiConverterTypeNonce.write(value.nonce, into: &buf)
        FfiConverterOptionString.write(value.methodName, into: &buf)
    }
}

public func FfiConverterTypeCredentialOffer_lift(_ buf: RustBuffer) throws -> CredentialOffer {
    return try FfiConverterTypeCredentialOffer.lift(buf)
}

public func FfiConverterTypeCredentialOffer_lower(_ value: CredentialOffer) -> RustBuffer {
    return FfiConverterTypeCredentialOffer.lower(value)
}

public struct IssuerId {
    public var id: String

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(id: String) {
        self.id = id
    }
}

extension IssuerId: Equatable, Hashable {
    public static func == (lhs: IssuerId, rhs: IssuerId) -> Bool {
        if lhs.id != rhs.id {
            return false
        }
        return true
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
}

public struct FfiConverterTypeIssuerId: FfiConverterRustBuffer {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> IssuerId {
        return try IssuerId(
            id: FfiConverterString.read(from: &buf)
        )
    }

    public static func write(_ value: IssuerId, into buf: inout [UInt8]) {
        FfiConverterString.write(value.id, into: &buf)
    }
}

public func FfiConverterTypeIssuerId_lift(_ buf: RustBuffer) throws -> IssuerId {
    return try FfiConverterTypeIssuerId.lift(buf)
}

public func FfiConverterTypeIssuerId_lower(_ value: IssuerId) -> RustBuffer {
    return FfiConverterTypeIssuerId.lower(value)
}

public struct SchemaId {
    public var id: String

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(id: String) {
        self.id = id
    }
}

extension SchemaId: Equatable, Hashable {
    public static func == (lhs: SchemaId, rhs: SchemaId) -> Bool {
        if lhs.id != rhs.id {
            return false
        }
        return true
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
}

public struct FfiConverterTypeSchemaId: FfiConverterRustBuffer {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> SchemaId {
        return try SchemaId(
            id: FfiConverterString.read(from: &buf)
        )
    }

    public static func write(_ value: SchemaId, into buf: inout [UInt8]) {
        FfiConverterString.write(value.id, into: &buf)
    }
}

public func FfiConverterTypeSchemaId_lift(_ buf: RustBuffer) throws -> SchemaId {
    return try FfiConverterTypeSchemaId.lift(buf)
}

public func FfiConverterTypeSchemaId_lower(_ value: SchemaId) -> RustBuffer {
    return FfiConverterTypeSchemaId.lower(value)
}

public struct SecretLink {
    public var secret: String

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(secret: String) {
        self.secret = secret
    }
}

extension SecretLink: Equatable, Hashable {
    public static func == (lhs: SecretLink, rhs: SecretLink) -> Bool {
        if lhs.secret != rhs.secret {
            return false
        }
        return true
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(secret)
    }
}

public struct FfiConverterTypeSecretLink: FfiConverterRustBuffer {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> SecretLink {
        return try SecretLink(
            secret: FfiConverterString.read(from: &buf)
        )
    }

    public static func write(_ value: SecretLink, into buf: inout [UInt8]) {
        FfiConverterString.write(value.secret, into: &buf)
    }
}

public func FfiConverterTypeSecretLink_lift(_ buf: RustBuffer) throws -> SecretLink {
    return try FfiConverterTypeSecretLink.lift(buf)
}

public func FfiConverterTypeSecretLink_lower(_ value: SecretLink) -> RustBuffer {
    return FfiConverterTypeSecretLink.lower(value)
}

// Note that we don't yet support `indirect` for enums.
// See https://github.com/mozilla/uniffi-rs/issues/396 for further discussion.
public enum SignatureType {
    case cl
}

public struct FfiConverterTypeSignatureType: FfiConverterRustBuffer {
    typealias SwiftType = SignatureType

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> SignatureType {
        let variant: Int32 = try readInt(&buf)
        switch variant {
        case 1: return .cl

        default: throw UniffiInternalError.unexpectedEnumCase
        }
    }

    public static func write(_ value: SignatureType, into buf: inout [UInt8]) {
        switch value {
        case .cl:
            writeInt(&buf, Int32(1))
        }
    }
}

public func FfiConverterTypeSignatureType_lift(_ buf: RustBuffer) throws -> SignatureType {
    return try FfiConverterTypeSignatureType.lift(buf)
}

public func FfiConverterTypeSignatureType_lower(_ value: SignatureType) -> RustBuffer {
    return FfiConverterTypeSignatureType.lower(value)
}

extension SignatureType: Equatable, Hashable {}

private struct FfiConverterOptionString: FfiConverterRustBuffer {
    typealias SwiftType = String?

    public static func write(_ value: SwiftType, into buf: inout [UInt8]) {
        guard let value = value else {
            writeInt(&buf, Int8(0))
            return
        }
        writeInt(&buf, Int8(1))
        FfiConverterString.write(value, into: &buf)
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> SwiftType {
        switch try readInt(&buf) as Int8 {
        case 0: return nil
        case 1: return try FfiConverterString.read(from: &buf)
        default: throw UniffiInternalError.unexpectedOptionalTag
        }
    }
}

/**
 * Top level initializers and tear down methods.
 *
 * This is generated by uniffi.
 */
public enum AnoncredsLifecycle {
    /**
     * Initialize the FFI and Rust library. This should be only called once per application.
     */
    func initialize() {}
}
