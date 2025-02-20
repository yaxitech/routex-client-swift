// swiftlint:disable all
import Foundation
import Foundation

// Depending on the consumer's build setup, the low-level FFI code
// might be in a separate module, or it might be compiled inline into
// this module. This is a bit of light hackery to work with both.
#if canImport(routex_clientFFI)
import routex_clientFFI
#endif

fileprivate extension RustBuffer {
    // Allocate a new buffer, copying the contents of a `UInt8` array.
    init(bytes: [UInt8]) {
        let rbuf = bytes.withUnsafeBufferPointer { ptr in
            RustBuffer.from(ptr)
        }
        self.init(capacity: rbuf.capacity, len: rbuf.len, data: rbuf.data)
    }

    static func empty() -> RustBuffer {
        RustBuffer(capacity: 0, len:0, data: nil)
    }

    static func from(_ ptr: UnsafeBufferPointer<UInt8>) -> RustBuffer {
        try! rustCall { ffi_routex_client_uniffi_rustbuffer_from_bytes(ForeignBytes(bufferPointer: ptr), $0) }
    }

    // Frees the buffer in place.
    // The buffer must not be used after this is called.
    func deallocate() {
        try! rustCall { ffi_routex_client_uniffi_rustbuffer_free(self, $0) }
    }
}

fileprivate extension ForeignBytes {
    init(bufferPointer: UnsafeBufferPointer<UInt8>) {
        self.init(len: Int32(bufferPointer.count), data: bufferPointer.baseAddress)
    }
}

// For every type used in the interface, we provide helper methods for conveniently
// lifting and lowering that type from C-compatible data, and for reading and writing
// values of that type in a buffer.

// Helper classes/extensions that don't change.
// Someday, this will be in a library of its own.

fileprivate extension Data {
    init(rustBuffer: RustBuffer) {
        self.init(
            bytesNoCopy: rustBuffer.data!,
            count: Int(rustBuffer.len),
            deallocator: .none
        )
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

fileprivate func createReader(data: Data) -> (data: Data, offset: Data.Index) {
    (data: data, offset: 0)
}

// Reads an integer at the current offset, in big-endian order, and advances
// the offset on success. Throws if reading the integer would move the
// offset past the end of the buffer.
fileprivate func readInt<T: FixedWidthInteger>(_ reader: inout (data: Data, offset: Data.Index)) throws -> T {
    let range = reader.offset..<reader.offset + MemoryLayout<T>.size
    guard reader.data.count >= range.upperBound else {
        throw UniffiInternalError.bufferOverflow
    }
    if T.self == UInt8.self {
        let value = reader.data[reader.offset]
        reader.offset += 1
        return value as! T
    }
    var value: T = 0
    let _ = withUnsafeMutableBytes(of: &value, { reader.data.copyBytes(to: $0, from: range)})
    reader.offset = range.upperBound
    return value.bigEndian
}

// Reads an arbitrary number of bytes, to be used to read
// raw bytes, this is useful when lifting strings
fileprivate func readBytes(_ reader: inout (data: Data, offset: Data.Index), count: Int) throws -> Array<UInt8> {
    let range = reader.offset..<(reader.offset+count)
    guard reader.data.count >= range.upperBound else {
        throw UniffiInternalError.bufferOverflow
    }
    var value = [UInt8](repeating: 0, count: count)
    value.withUnsafeMutableBufferPointer({ buffer in
        reader.data.copyBytes(to: buffer, from: range)
    })
    reader.offset = range.upperBound
    return value
}

// Reads a float at the current offset.
fileprivate func readFloat(_ reader: inout (data: Data, offset: Data.Index)) throws -> Float {
    return Float(bitPattern: try readInt(&reader))
}

// Reads a float at the current offset.
fileprivate func readDouble(_ reader: inout (data: Data, offset: Data.Index)) throws -> Double {
    return Double(bitPattern: try readInt(&reader))
}

// Indicates if the offset has reached the end of the buffer.
fileprivate func hasRemaining(_ reader: (data: Data, offset: Data.Index)) -> Bool {
    return reader.offset < reader.data.count
}

// Define writer functionality.  Normally this would be defined in a class or
// struct, but we use standalone functions instead in order to make external
// types work.  See the above discussion on Readers for details.

fileprivate func createWriter() -> [UInt8] {
    return []
}

fileprivate func writeBytes<S>(_ writer: inout [UInt8], _ byteArr: S) where S: Sequence, S.Element == UInt8 {
    writer.append(contentsOf: byteArr)
}

// Writes an integer in big-endian order.
//
// Warning: make sure what you are trying to write
// is in the correct type!
fileprivate func writeInt<T: FixedWidthInteger>(_ writer: inout [UInt8], _ value: T) {
    var value = value.bigEndian
    withUnsafeBytes(of: &value) { writer.append(contentsOf: $0) }
}

fileprivate func writeFloat(_ writer: inout [UInt8], _ value: Float) {
    writeInt(&writer, value.bitPattern)
}

fileprivate func writeDouble(_ writer: inout [UInt8], _ value: Double) {
    writeInt(&writer, value.bitPattern)
}

// Protocol for types that transfer other types across the FFI. This is
// analogous to the Rust trait of the same name.
fileprivate protocol FfiConverter {
    associatedtype FfiType
    associatedtype SwiftType

    static func lift(_ value: FfiType) throws -> SwiftType
    static func lower(_ value: SwiftType) -> FfiType
    static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> SwiftType
    static func write(_ value: SwiftType, into buf: inout [UInt8])
}

// Types conforming to `Primitive` pass themselves directly over the FFI.
fileprivate protocol FfiConverterPrimitive: FfiConverter where FfiType == SwiftType { }

extension FfiConverterPrimitive {
#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public static func lift(_ value: FfiType) throws -> SwiftType {
        return value
    }

#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public static func lower(_ value: SwiftType) -> FfiType {
        return value
    }
}

// Types conforming to `FfiConverterRustBuffer` lift and lower into a `RustBuffer`.
// Used for complex types where it's hard to write a custom lift/lower.
fileprivate protocol FfiConverterRustBuffer: FfiConverter where FfiType == RustBuffer {}

extension FfiConverterRustBuffer {
#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public static func lift(_ buf: RustBuffer) throws -> SwiftType {
        var reader = createReader(data: Data(rustBuffer: buf))
        let value = try read(from: &reader)
        if hasRemaining(reader) {
            throw UniffiInternalError.incompleteData
        }
        buf.deallocate()
        return value
    }

#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public static func lower(_ value: SwiftType) -> RustBuffer {
          var writer = createWriter()
          write(value, into: &writer)
          return RustBuffer(bytes: writer)
    }
}
// An error type for FFI errors. These errors occur at the UniFFI level, not
// the library level.
fileprivate enum UniffiInternalError: LocalizedError {
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

fileprivate extension NSLock {
    func withLock<T>(f: () throws -> T) rethrows -> T {
        self.lock()
        defer { self.unlock() }
        return try f()
    }
}

fileprivate let CALL_SUCCESS: Int8 = 0
fileprivate let CALL_ERROR: Int8 = 1
fileprivate let CALL_UNEXPECTED_ERROR: Int8 = 2
fileprivate let CALL_CANCELLED: Int8 = 3

fileprivate extension RustCallStatus {
    init() {
        self.init(
            code: CALL_SUCCESS,
            errorBuf: RustBuffer.init(
                capacity: 0,
                len: 0,
                data: nil
            )
        )
    }
}

private func rustCall<T>(_ callback: (UnsafeMutablePointer<RustCallStatus>) -> T) throws -> T {
    let neverThrow: ((RustBuffer) throws -> Never)? = nil
    return try makeRustCall(callback, errorHandler: neverThrow)
}

private func rustCallWithError<T, E: Swift.Error>(
    _ errorHandler: @escaping (RustBuffer) throws -> E,
    _ callback: (UnsafeMutablePointer<RustCallStatus>) -> T) throws -> T {
    try makeRustCall(callback, errorHandler: errorHandler)
}

private func makeRustCall<T, E: Swift.Error>(
    _ callback: (UnsafeMutablePointer<RustCallStatus>) -> T,
    errorHandler: ((RustBuffer) throws -> E)?
) throws -> T {
    uniffiEnsureRoutexClientUniffiInitialized()
    var callStatus = RustCallStatus.init()
    let returnedVal = callback(&callStatus)
    try uniffiCheckCallStatus(callStatus: callStatus, errorHandler: errorHandler)
    return returnedVal
}

private func uniffiCheckCallStatus<E: Swift.Error>(
    callStatus: RustCallStatus,
    errorHandler: ((RustBuffer) throws -> E)?
) throws {
    switch callStatus.code {
        case CALL_SUCCESS:
            return

        case CALL_ERROR:
            if let errorHandler = errorHandler {
                throw try errorHandler(callStatus.errorBuf)
            } else {
                callStatus.errorBuf.deallocate()
                throw UniffiInternalError.unexpectedRustCallError
            }

        case CALL_UNEXPECTED_ERROR:
            // When the rust code sees a panic, it tries to construct a RustBuffer
            // with the message.  But if that code panics, then it just sends back
            // an empty buffer.
            if callStatus.errorBuf.len > 0 {
                throw UniffiInternalError.rustPanic(try FfiConverterString.lift(callStatus.errorBuf))
            } else {
                callStatus.errorBuf.deallocate()
                throw UniffiInternalError.rustPanic("Rust panic")
            }

        case CALL_CANCELLED:
            fatalError("Cancellation not supported yet")

        default:
            throw UniffiInternalError.unexpectedRustCallStatusCode
    }
}

private func uniffiTraitInterfaceCall<T>(
    callStatus: UnsafeMutablePointer<RustCallStatus>,
    makeCall: () throws -> T,
    writeReturn: (T) -> ()
) {
    do {
        try writeReturn(makeCall())
    } catch let error {
        callStatus.pointee.code = CALL_UNEXPECTED_ERROR
        callStatus.pointee.errorBuf = FfiConverterString.lower(String(describing: error))
    }
}

private func uniffiTraitInterfaceCallWithError<T, E>(
    callStatus: UnsafeMutablePointer<RustCallStatus>,
    makeCall: () throws -> T,
    writeReturn: (T) -> (),
    lowerError: (E) -> RustBuffer
) {
    do {
        try writeReturn(makeCall())
    } catch let error as E {
        callStatus.pointee.code = CALL_ERROR
        callStatus.pointee.errorBuf = lowerError(error)
    } catch {
        callStatus.pointee.code = CALL_UNEXPECTED_ERROR
        callStatus.pointee.errorBuf = FfiConverterString.lower(String(describing: error))
    }
}
fileprivate final class UniffiHandleMap<T>: @unchecked Sendable {
    // All mutation happens with this lock held, which is why we implement @unchecked Sendable.
    private let lock = NSLock()
    private var map: [UInt64: T] = [:]
    private var currentHandle: UInt64 = 1

    func insert(obj: T) -> UInt64 {
        lock.withLock {
            let handle = currentHandle
            currentHandle += 1
            map[handle] = obj
            return handle
        }
    }

     func get(handle: UInt64) throws -> T {
        try lock.withLock {
            guard let obj = map[handle] else {
                throw UniffiInternalError.unexpectedStaleHandle
            }
            return obj
        }
    }

    @discardableResult
    func remove(handle: UInt64) throws -> T {
        try lock.withLock {
            guard let obj = map.removeValue(forKey: handle) else {
                throw UniffiInternalError.unexpectedStaleHandle
            }
            return obj
        }
    }

    var count: Int {
        get {
            map.count
        }
    }
}


// Public interface members begin here.


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterUInt32: FfiConverterPrimitive {
    typealias FfiType = UInt32
    typealias SwiftType = UInt32

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> UInt32 {
        return try lift(readInt(&buf))
    }

    public static func write(_ value: SwiftType, into buf: inout [UInt8]) {
        writeInt(&buf, lower(value))
    }
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterBool : FfiConverter {
    typealias FfiType = Int8
    typealias SwiftType = Bool

    public static func lift(_ value: Int8) throws -> Bool {
        return value != 0
    }

    public static func lower(_ value: Bool) -> Int8 {
        return value ? 1 : 0
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> Bool {
        return try lift(readInt(&buf))
    }

    public static func write(_ value: Bool, into buf: inout [UInt8]) {
        writeInt(&buf, lower(value))
    }
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterString: FfiConverter {
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

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterData: FfiConverterRustBuffer {
    typealias SwiftType = Data

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> Data {
        let len: Int32 = try readInt(&buf)
        return Data(try readBytes(&buf, count: Int(len)))
    }

    public static func write(_ value: Data, into buf: inout [UInt8]) {
        let len = Int32(value.count)
        writeInt(&buf, len)
        writeBytes(&buf, value)
    }
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterTimestamp: FfiConverterRustBuffer {
    typealias SwiftType = Date

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> Date {
        let seconds: Int64 = try readInt(&buf)
        let nanoseconds: UInt32 = try readInt(&buf)
        if seconds >= 0 {
            let delta = Double(seconds) + (Double(nanoseconds) / 1.0e9)
            return Date.init(timeIntervalSince1970: delta)
        } else {
            let delta = Double(seconds) - (Double(nanoseconds) / 1.0e9)
            return Date.init(timeIntervalSince1970: delta)
        }
    }

    public static func write(_ value: Date, into buf: inout [UInt8]) {
        var delta = value.timeIntervalSince1970
        var sign: Int64 = 1
        if delta < 0 {
            // The nanoseconds portion of the epoch offset must always be
            // positive, to simplify the calculation we will use the absolute
            // value of the offset.
            sign = -1
            delta = -delta
        }
        if delta.rounded(.down) > Double(Int64.max) {
            fatalError("Timestamp overflow, exceeds max bounds supported by Uniffi")
        }
        let seconds = Int64(delta)
        let nanoseconds = UInt32((delta - Double(seconds)) * 1.0e9)
        writeInt(&buf, sign * seconds)
        writeInt(&buf, nanoseconds)
    }
}




public protocol AuthenticatedAccountsResultProtocol: AnyObject {
    
    func jwt()  -> String
    
    func toData()  -> AccountsResult
    
}
open class AuthenticatedAccountsResult: AuthenticatedAccountsResultProtocol, @unchecked Sendable {
    fileprivate let pointer: UnsafeMutableRawPointer!

    /// Used to instantiate a [FFIObject] without an actual pointer, for fakes in tests, mostly.
#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public struct NoPointer {
        public init() {}
    }

    // TODO: We'd like this to be `private` but for Swifty reasons,
    // we can't implement `FfiConverter` without making this `required` and we can't
    // make it `required` without making it `public`.
    required public init(unsafeFromRawPointer pointer: UnsafeMutableRawPointer) {
        self.pointer = pointer
    }

    // This constructor can be used to instantiate a fake object.
    // - Parameter noPointer: Placeholder value so we can have a constructor separate from the default empty one that may be implemented for classes extending [FFIObject].
    //
    // - Warning:
    //     Any object instantiated with this constructor cannot be passed to an actual Rust-backed object. Since there isn't a backing [Pointer] the FFI lower functions will crash.
#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public init(noPointer: NoPointer) {
        self.pointer = nil
    }

#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public func uniffiClonePointer() -> UnsafeMutableRawPointer {
        return try! rustCall { uniffi_routex_client_uniffi_fn_clone_authenticatedaccountsresult(self.pointer, $0) }
    }
    // No primary constructor declared for this class.

    deinit {
        guard let pointer = pointer else {
            return
        }

        try! rustCall { uniffi_routex_client_uniffi_fn_free_authenticatedaccountsresult(pointer, $0) }
    }

    

    
open func jwt() -> String  {
    return try!  FfiConverterString.lift(try! rustCall() {
    uniffi_routex_client_uniffi_fn_method_authenticatedaccountsresult_jwt(self.uniffiClonePointer(),$0
    )
})
}
    
open func toData() -> AccountsResult  {
    return try!  FfiConverterTypeAccountsResult_lift(try! rustCall() {
    uniffi_routex_client_uniffi_fn_method_authenticatedaccountsresult_to_data(self.uniffiClonePointer(),$0
    )
})
}
    

}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeAuthenticatedAccountsResult: FfiConverter {

    typealias FfiType = UnsafeMutableRawPointer
    typealias SwiftType = AuthenticatedAccountsResult

    public static func lift(_ pointer: UnsafeMutableRawPointer) throws -> AuthenticatedAccountsResult {
        return AuthenticatedAccountsResult(unsafeFromRawPointer: pointer)
    }

    public static func lower(_ value: AuthenticatedAccountsResult) -> UnsafeMutableRawPointer {
        return value.uniffiClonePointer()
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> AuthenticatedAccountsResult {
        let v: UInt64 = try readInt(&buf)
        // The Rust code won't compile if a pointer won't fit in a UInt64.
        // We have to go via `UInt` because that's the thing that's the size of a pointer.
        let ptr = UnsafeMutableRawPointer(bitPattern: UInt(truncatingIfNeeded: v))
        if (ptr == nil) {
            throw UniffiInternalError.unexpectedNullPointer
        }
        return try lift(ptr!)
    }

    public static func write(_ value: AuthenticatedAccountsResult, into buf: inout [UInt8]) {
        // This fiddling is because `Int` is the thing that's the same size as a pointer.
        // The Rust code won't compile if a pointer won't fit in a `UInt64`.
        writeInt(&buf, UInt64(bitPattern: Int64(Int(bitPattern: lower(value)))))
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAuthenticatedAccountsResult_lift(_ pointer: UnsafeMutableRawPointer) throws -> AuthenticatedAccountsResult {
    return try FfiConverterTypeAuthenticatedAccountsResult.lift(pointer)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAuthenticatedAccountsResult_lower(_ value: AuthenticatedAccountsResult) -> UnsafeMutableRawPointer {
    return FfiConverterTypeAuthenticatedAccountsResult.lower(value)
}






public protocol AuthenticatedCollectPaymentResultProtocol: AnyObject {
    
    func jwt()  -> String
    
    func toData()  -> CollectPaymentResult
    
}
open class AuthenticatedCollectPaymentResult: AuthenticatedCollectPaymentResultProtocol, @unchecked Sendable {
    fileprivate let pointer: UnsafeMutableRawPointer!

    /// Used to instantiate a [FFIObject] without an actual pointer, for fakes in tests, mostly.
#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public struct NoPointer {
        public init() {}
    }

    // TODO: We'd like this to be `private` but for Swifty reasons,
    // we can't implement `FfiConverter` without making this `required` and we can't
    // make it `required` without making it `public`.
    required public init(unsafeFromRawPointer pointer: UnsafeMutableRawPointer) {
        self.pointer = pointer
    }

    // This constructor can be used to instantiate a fake object.
    // - Parameter noPointer: Placeholder value so we can have a constructor separate from the default empty one that may be implemented for classes extending [FFIObject].
    //
    // - Warning:
    //     Any object instantiated with this constructor cannot be passed to an actual Rust-backed object. Since there isn't a backing [Pointer] the FFI lower functions will crash.
#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public init(noPointer: NoPointer) {
        self.pointer = nil
    }

#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public func uniffiClonePointer() -> UnsafeMutableRawPointer {
        return try! rustCall { uniffi_routex_client_uniffi_fn_clone_authenticatedcollectpaymentresult(self.pointer, $0) }
    }
    // No primary constructor declared for this class.

    deinit {
        guard let pointer = pointer else {
            return
        }

        try! rustCall { uniffi_routex_client_uniffi_fn_free_authenticatedcollectpaymentresult(pointer, $0) }
    }

    

    
open func jwt() -> String  {
    return try!  FfiConverterString.lift(try! rustCall() {
    uniffi_routex_client_uniffi_fn_method_authenticatedcollectpaymentresult_jwt(self.uniffiClonePointer(),$0
    )
})
}
    
open func toData() -> CollectPaymentResult  {
    return try!  FfiConverterTypeCollectPaymentResult_lift(try! rustCall() {
    uniffi_routex_client_uniffi_fn_method_authenticatedcollectpaymentresult_to_data(self.uniffiClonePointer(),$0
    )
})
}
    

}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeAuthenticatedCollectPaymentResult: FfiConverter {

    typealias FfiType = UnsafeMutableRawPointer
    typealias SwiftType = AuthenticatedCollectPaymentResult

    public static func lift(_ pointer: UnsafeMutableRawPointer) throws -> AuthenticatedCollectPaymentResult {
        return AuthenticatedCollectPaymentResult(unsafeFromRawPointer: pointer)
    }

    public static func lower(_ value: AuthenticatedCollectPaymentResult) -> UnsafeMutableRawPointer {
        return value.uniffiClonePointer()
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> AuthenticatedCollectPaymentResult {
        let v: UInt64 = try readInt(&buf)
        // The Rust code won't compile if a pointer won't fit in a UInt64.
        // We have to go via `UInt` because that's the thing that's the size of a pointer.
        let ptr = UnsafeMutableRawPointer(bitPattern: UInt(truncatingIfNeeded: v))
        if (ptr == nil) {
            throw UniffiInternalError.unexpectedNullPointer
        }
        return try lift(ptr!)
    }

    public static func write(_ value: AuthenticatedCollectPaymentResult, into buf: inout [UInt8]) {
        // This fiddling is because `Int` is the thing that's the same size as a pointer.
        // The Rust code won't compile if a pointer won't fit in a `UInt64`.
        writeInt(&buf, UInt64(bitPattern: Int64(Int(bitPattern: lower(value)))))
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAuthenticatedCollectPaymentResult_lift(_ pointer: UnsafeMutableRawPointer) throws -> AuthenticatedCollectPaymentResult {
    return try FfiConverterTypeAuthenticatedCollectPaymentResult.lift(pointer)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAuthenticatedCollectPaymentResult_lower(_ value: AuthenticatedCollectPaymentResult) -> UnsafeMutableRawPointer {
    return FfiConverterTypeAuthenticatedCollectPaymentResult.lower(value)
}






public protocol AuthenticatedTransactionsResultProtocol: AnyObject {
    
    func jwt()  -> String
    
    func toData()  -> TransactionsResult
    
}
open class AuthenticatedTransactionsResult: AuthenticatedTransactionsResultProtocol, @unchecked Sendable {
    fileprivate let pointer: UnsafeMutableRawPointer!

    /// Used to instantiate a [FFIObject] without an actual pointer, for fakes in tests, mostly.
#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public struct NoPointer {
        public init() {}
    }

    // TODO: We'd like this to be `private` but for Swifty reasons,
    // we can't implement `FfiConverter` without making this `required` and we can't
    // make it `required` without making it `public`.
    required public init(unsafeFromRawPointer pointer: UnsafeMutableRawPointer) {
        self.pointer = pointer
    }

    // This constructor can be used to instantiate a fake object.
    // - Parameter noPointer: Placeholder value so we can have a constructor separate from the default empty one that may be implemented for classes extending [FFIObject].
    //
    // - Warning:
    //     Any object instantiated with this constructor cannot be passed to an actual Rust-backed object. Since there isn't a backing [Pointer] the FFI lower functions will crash.
#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public init(noPointer: NoPointer) {
        self.pointer = nil
    }

#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public func uniffiClonePointer() -> UnsafeMutableRawPointer {
        return try! rustCall { uniffi_routex_client_uniffi_fn_clone_authenticatedtransactionsresult(self.pointer, $0) }
    }
    // No primary constructor declared for this class.

    deinit {
        guard let pointer = pointer else {
            return
        }

        try! rustCall { uniffi_routex_client_uniffi_fn_free_authenticatedtransactionsresult(pointer, $0) }
    }

    

    
open func jwt() -> String  {
    return try!  FfiConverterString.lift(try! rustCall() {
    uniffi_routex_client_uniffi_fn_method_authenticatedtransactionsresult_jwt(self.uniffiClonePointer(),$0
    )
})
}
    
open func toData() -> TransactionsResult  {
    return try!  FfiConverterTypeTransactionsResult_lift(try! rustCall() {
    uniffi_routex_client_uniffi_fn_method_authenticatedtransactionsresult_to_data(self.uniffiClonePointer(),$0
    )
})
}
    

}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeAuthenticatedTransactionsResult: FfiConverter {

    typealias FfiType = UnsafeMutableRawPointer
    typealias SwiftType = AuthenticatedTransactionsResult

    public static func lift(_ pointer: UnsafeMutableRawPointer) throws -> AuthenticatedTransactionsResult {
        return AuthenticatedTransactionsResult(unsafeFromRawPointer: pointer)
    }

    public static func lower(_ value: AuthenticatedTransactionsResult) -> UnsafeMutableRawPointer {
        return value.uniffiClonePointer()
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> AuthenticatedTransactionsResult {
        let v: UInt64 = try readInt(&buf)
        // The Rust code won't compile if a pointer won't fit in a UInt64.
        // We have to go via `UInt` because that's the thing that's the size of a pointer.
        let ptr = UnsafeMutableRawPointer(bitPattern: UInt(truncatingIfNeeded: v))
        if (ptr == nil) {
            throw UniffiInternalError.unexpectedNullPointer
        }
        return try lift(ptr!)
    }

    public static func write(_ value: AuthenticatedTransactionsResult, into buf: inout [UInt8]) {
        // This fiddling is because `Int` is the thing that's the same size as a pointer.
        // The Rust code won't compile if a pointer won't fit in a `UInt64`.
        writeInt(&buf, UInt64(bitPattern: Int64(Int(bitPattern: lower(value)))))
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAuthenticatedTransactionsResult_lift(_ pointer: UnsafeMutableRawPointer) throws -> AuthenticatedTransactionsResult {
    return try FfiConverterTypeAuthenticatedTransactionsResult.lift(pointer)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAuthenticatedTransactionsResult_lower(_ value: AuthenticatedTransactionsResult) -> UnsafeMutableRawPointer {
    return FfiConverterTypeAuthenticatedTransactionsResult.lower(value)
}






public protocol RoutexClientProtocol: AnyObject {
    
    func accounts(credentials: Credentials, session: Session?, ticket: Ticket, fields: [AccountField], filter: AccountFilter?) async throws  -> AccountsResponse
    
    func collectPayment(credentials: Credentials, session: Session?, ticket: Ticket, account: AccountReference?) async throws  -> CollectPaymentResponse
    
    func confirmAccounts(ticket: Ticket, context: ConfirmationContext) async throws  -> AccountsResponse
    
    func confirmCollectPayment(ticket: Ticket, context: ConfirmationContext) async throws  -> CollectPaymentResponse
    
    func confirmTransactions(ticket: Ticket, context: ConfirmationContext) async throws  -> TransactionsResponse
    
    func info(ticket: Ticket, connectionId: ConnectionId) async throws  -> ConnectionInfo
    
    func registerRedirectUri(ticket: Ticket, handle: String, redirectUri: String) async throws  -> Url
    
    func respondAccounts(ticket: Ticket, context: InputContext, response: String) async throws  -> AccountsResponse
    
    func respondCollectPayment(ticket: Ticket, context: InputContext, response: String) async throws  -> CollectPaymentResponse
    
    func respondTransactions(ticket: Ticket, context: InputContext, response: String) async throws  -> TransactionsResponse
    
    func search(ticket: Ticket, filters: [SearchFilter], ibanDetection: Bool, limit: UInt32?) async throws  -> [ConnectionInfo]
    
    func setRedirectUri(redirectUri: String) throws 
    
    func settleKey(ticket: Ticket) async throws 
    
    func trace(ticket: Ticket, traceId: Data) async throws  -> String
    
    func traceId()  -> Data?
    
    func transactions(credentials: Credentials, session: Session?, ticket: Ticket) async throws  -> TransactionsResponse
    
}
open class RoutexClient: RoutexClientProtocol, @unchecked Sendable {
    fileprivate let pointer: UnsafeMutableRawPointer!

    /// Used to instantiate a [FFIObject] without an actual pointer, for fakes in tests, mostly.
#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public struct NoPointer {
        public init() {}
    }

    // TODO: We'd like this to be `private` but for Swifty reasons,
    // we can't implement `FfiConverter` without making this `required` and we can't
    // make it `required` without making it `public`.
    required public init(unsafeFromRawPointer pointer: UnsafeMutableRawPointer) {
        self.pointer = pointer
    }

    // This constructor can be used to instantiate a fake object.
    // - Parameter noPointer: Placeholder value so we can have a constructor separate from the default empty one that may be implemented for classes extending [FFIObject].
    //
    // - Warning:
    //     Any object instantiated with this constructor cannot be passed to an actual Rust-backed object. Since there isn't a backing [Pointer] the FFI lower functions will crash.
#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public init(noPointer: NoPointer) {
        self.pointer = nil
    }

#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public func uniffiClonePointer() -> UnsafeMutableRawPointer {
        return try! rustCall { uniffi_routex_client_uniffi_fn_clone_routexclient(self.pointer, $0) }
    }
public convenience init(distribution: String, version: String, url: Url) {
    let pointer =
        try! rustCall() {
    uniffi_routex_client_uniffi_fn_constructor_routexclient_new(
        FfiConverterString.lower(distribution),
        FfiConverterString.lower(version),
        FfiConverterTypeUrl_lower(url),$0
    )
}
    self.init(unsafeFromRawPointer: pointer)
}

    deinit {
        guard let pointer = pointer else {
            return
        }

        try! rustCall { uniffi_routex_client_uniffi_fn_free_routexclient(pointer, $0) }
    }

    

    
open func accounts(credentials: Credentials, session: Session?, ticket: Ticket, fields: [AccountField], filter: AccountFilter? = nil)async throws  -> AccountsResponse  {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_accounts(
                    self.uniffiClonePointer(),
                    FfiConverterTypeCredentials_lower(credentials),FfiConverterOptionTypeSession.lower(session),FfiConverterTypeTicket_lower(ticket),FfiConverterSequenceTypeAccountField.lower(fields),FfiConverterOptionTypeAccountFilter.lower(filter)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_rust_buffer,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_rust_buffer,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_rust_buffer,
            liftFunc: FfiConverterTypeAccountsResponse_lift,
            errorHandler: FfiConverterTypeRoutexClientError.lift
        )
}
    
open func collectPayment(credentials: Credentials, session: Session?, ticket: Ticket, account: AccountReference? = nil)async throws  -> CollectPaymentResponse  {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_collect_payment(
                    self.uniffiClonePointer(),
                    FfiConverterTypeCredentials_lower(credentials),FfiConverterOptionTypeSession.lower(session),FfiConverterTypeTicket_lower(ticket),FfiConverterOptionTypeAccountReference.lower(account)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_rust_buffer,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_rust_buffer,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_rust_buffer,
            liftFunc: FfiConverterTypeCollectPaymentResponse_lift,
            errorHandler: FfiConverterTypeRoutexClientError.lift
        )
}
    
open func confirmAccounts(ticket: Ticket, context: ConfirmationContext)async throws  -> AccountsResponse  {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_confirm_accounts(
                    self.uniffiClonePointer(),
                    FfiConverterTypeTicket_lower(ticket),FfiConverterTypeConfirmationContext_lower(context)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_rust_buffer,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_rust_buffer,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_rust_buffer,
            liftFunc: FfiConverterTypeAccountsResponse_lift,
            errorHandler: FfiConverterTypeRoutexClientError.lift
        )
}
    
open func confirmCollectPayment(ticket: Ticket, context: ConfirmationContext)async throws  -> CollectPaymentResponse  {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_confirm_collect_payment(
                    self.uniffiClonePointer(),
                    FfiConverterTypeTicket_lower(ticket),FfiConverterTypeConfirmationContext_lower(context)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_rust_buffer,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_rust_buffer,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_rust_buffer,
            liftFunc: FfiConverterTypeCollectPaymentResponse_lift,
            errorHandler: FfiConverterTypeRoutexClientError.lift
        )
}
    
open func confirmTransactions(ticket: Ticket, context: ConfirmationContext)async throws  -> TransactionsResponse  {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_confirm_transactions(
                    self.uniffiClonePointer(),
                    FfiConverterTypeTicket_lower(ticket),FfiConverterTypeConfirmationContext_lower(context)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_rust_buffer,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_rust_buffer,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_rust_buffer,
            liftFunc: FfiConverterTypeTransactionsResponse_lift,
            errorHandler: FfiConverterTypeRoutexClientError.lift
        )
}
    
open func info(ticket: Ticket, connectionId: ConnectionId)async throws  -> ConnectionInfo  {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_info(
                    self.uniffiClonePointer(),
                    FfiConverterTypeTicket_lower(ticket),FfiConverterTypeConnectionId_lower(connectionId)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_rust_buffer,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_rust_buffer,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_rust_buffer,
            liftFunc: FfiConverterTypeConnectionInfo_lift,
            errorHandler: FfiConverterTypeRoutexClientError.lift
        )
}
    
open func registerRedirectUri(ticket: Ticket, handle: String, redirectUri: String)async throws  -> Url  {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_register_redirect_uri(
                    self.uniffiClonePointer(),
                    FfiConverterTypeTicket_lower(ticket),FfiConverterString.lower(handle),FfiConverterString.lower(redirectUri)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_rust_buffer,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_rust_buffer,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_rust_buffer,
            liftFunc: FfiConverterTypeUrl_lift,
            errorHandler: FfiConverterTypeRoutexClientError.lift
        )
}
    
open func respondAccounts(ticket: Ticket, context: InputContext, response: String)async throws  -> AccountsResponse  {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_respond_accounts(
                    self.uniffiClonePointer(),
                    FfiConverterTypeTicket_lower(ticket),FfiConverterTypeInputContext_lower(context),FfiConverterString.lower(response)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_rust_buffer,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_rust_buffer,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_rust_buffer,
            liftFunc: FfiConverterTypeAccountsResponse_lift,
            errorHandler: FfiConverterTypeRoutexClientError.lift
        )
}
    
open func respondCollectPayment(ticket: Ticket, context: InputContext, response: String)async throws  -> CollectPaymentResponse  {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_respond_collect_payment(
                    self.uniffiClonePointer(),
                    FfiConverterTypeTicket_lower(ticket),FfiConverterTypeInputContext_lower(context),FfiConverterString.lower(response)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_rust_buffer,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_rust_buffer,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_rust_buffer,
            liftFunc: FfiConverterTypeCollectPaymentResponse_lift,
            errorHandler: FfiConverterTypeRoutexClientError.lift
        )
}
    
open func respondTransactions(ticket: Ticket, context: InputContext, response: String)async throws  -> TransactionsResponse  {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_respond_transactions(
                    self.uniffiClonePointer(),
                    FfiConverterTypeTicket_lower(ticket),FfiConverterTypeInputContext_lower(context),FfiConverterString.lower(response)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_rust_buffer,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_rust_buffer,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_rust_buffer,
            liftFunc: FfiConverterTypeTransactionsResponse_lift,
            errorHandler: FfiConverterTypeRoutexClientError.lift
        )
}
    
open func search(ticket: Ticket, filters: [SearchFilter], ibanDetection: Bool, limit: UInt32? = nil)async throws  -> [ConnectionInfo]  {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_search(
                    self.uniffiClonePointer(),
                    FfiConverterTypeTicket_lower(ticket),FfiConverterSequenceTypeSearchFilter.lower(filters),FfiConverterBool.lower(ibanDetection),FfiConverterOptionUInt32.lower(limit)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_rust_buffer,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_rust_buffer,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_rust_buffer,
            liftFunc: FfiConverterSequenceTypeConnectionInfo.lift,
            errorHandler: FfiConverterTypeRoutexClientError.lift
        )
}
    
open func setRedirectUri(redirectUri: String)throws   {try rustCallWithError(FfiConverterTypeRoutexClientError_lift) {
    uniffi_routex_client_uniffi_fn_method_routexclient_set_redirect_uri(self.uniffiClonePointer(),
        FfiConverterString.lower(redirectUri),$0
    )
}
}
    
open func settleKey(ticket: Ticket)async throws   {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_settle_key(
                    self.uniffiClonePointer(),
                    FfiConverterTypeTicket_lower(ticket)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_void,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_void,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_void,
            liftFunc: { $0 },
            errorHandler: FfiConverterTypeRoutexClientError.lift
        )
}
    
open func trace(ticket: Ticket, traceId: Data)async throws  -> String  {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_trace(
                    self.uniffiClonePointer(),
                    FfiConverterTypeTicket_lower(ticket),FfiConverterData.lower(traceId)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_rust_buffer,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_rust_buffer,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_rust_buffer,
            liftFunc: FfiConverterString.lift,
            errorHandler: FfiConverterTypeRoutexClientError.lift
        )
}
    
open func traceId() -> Data?  {
    return try!  FfiConverterOptionData.lift(try! rustCall() {
    uniffi_routex_client_uniffi_fn_method_routexclient_trace_id(self.uniffiClonePointer(),$0
    )
})
}
    
open func transactions(credentials: Credentials, session: Session?, ticket: Ticket)async throws  -> TransactionsResponse  {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_transactions(
                    self.uniffiClonePointer(),
                    FfiConverterTypeCredentials_lower(credentials),FfiConverterOptionTypeSession.lower(session),FfiConverterTypeTicket_lower(ticket)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_rust_buffer,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_rust_buffer,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_rust_buffer,
            liftFunc: FfiConverterTypeTransactionsResponse_lift,
            errorHandler: FfiConverterTypeRoutexClientError.lift
        )
}
    

}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeRoutexClient: FfiConverter {

    typealias FfiType = UnsafeMutableRawPointer
    typealias SwiftType = RoutexClient

    public static func lift(_ pointer: UnsafeMutableRawPointer) throws -> RoutexClient {
        return RoutexClient(unsafeFromRawPointer: pointer)
    }

    public static func lower(_ value: RoutexClient) -> UnsafeMutableRawPointer {
        return value.uniffiClonePointer()
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> RoutexClient {
        let v: UInt64 = try readInt(&buf)
        // The Rust code won't compile if a pointer won't fit in a UInt64.
        // We have to go via `UInt` because that's the thing that's the size of a pointer.
        let ptr = UnsafeMutableRawPointer(bitPattern: UInt(truncatingIfNeeded: v))
        if (ptr == nil) {
            throw UniffiInternalError.unexpectedNullPointer
        }
        return try lift(ptr!)
    }

    public static func write(_ value: RoutexClient, into buf: inout [UInt8]) {
        // This fiddling is because `Int` is the thing that's the same size as a pointer.
        // The Rust code won't compile if a pointer won't fit in a `UInt64`.
        writeInt(&buf, UInt64(bitPattern: Int64(Int(bitPattern: lower(value)))))
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeRoutexClient_lift(_ pointer: UnsafeMutableRawPointer) throws -> RoutexClient {
    return try FfiConverterTypeRoutexClient.lift(pointer)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeRoutexClient_lower(_ value: RoutexClient) -> UnsafeMutableRawPointer {
    return FfiConverterTypeRoutexClient.lower(value)
}




public struct AccountsResult {
    public var data: [Account]
    public var ticketId: String
    public var timestamp: Date

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(data: [Account], ticketId: String, timestamp: Date) {
        self.data = data
        self.ticketId = ticketId
        self.timestamp = timestamp
    }
}

#if compiler(>=6)
extension AccountsResult: Sendable {}
#endif


extension AccountsResult: Equatable, Hashable {
    public static func ==(lhs: AccountsResult, rhs: AccountsResult) -> Bool {
        if lhs.data != rhs.data {
            return false
        }
        if lhs.ticketId != rhs.ticketId {
            return false
        }
        if lhs.timestamp != rhs.timestamp {
            return false
        }
        return true
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(data)
        hasher.combine(ticketId)
        hasher.combine(timestamp)
    }
}



#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeAccountsResult: FfiConverterRustBuffer {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> AccountsResult {
        return
            try AccountsResult(
                data: FfiConverterSequenceTypeAccount.read(from: &buf), 
                ticketId: FfiConverterString.read(from: &buf), 
                timestamp: FfiConverterTimestamp.read(from: &buf)
        )
    }

    public static func write(_ value: AccountsResult, into buf: inout [UInt8]) {
        FfiConverterSequenceTypeAccount.write(value.data, into: &buf)
        FfiConverterString.write(value.ticketId, into: &buf)
        FfiConverterTimestamp.write(value.timestamp, into: &buf)
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAccountsResult_lift(_ buf: RustBuffer) throws -> AccountsResult {
    return try FfiConverterTypeAccountsResult.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAccountsResult_lower(_ value: AccountsResult) -> RustBuffer {
    return FfiConverterTypeAccountsResult.lower(value)
}


public struct CollectPaymentResult {
    public var ticketId: String
    public var timestamp: Date

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(ticketId: String, timestamp: Date) {
        self.ticketId = ticketId
        self.timestamp = timestamp
    }
}

#if compiler(>=6)
extension CollectPaymentResult: Sendable {}
#endif


extension CollectPaymentResult: Equatable, Hashable {
    public static func ==(lhs: CollectPaymentResult, rhs: CollectPaymentResult) -> Bool {
        if lhs.ticketId != rhs.ticketId {
            return false
        }
        if lhs.timestamp != rhs.timestamp {
            return false
        }
        return true
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(ticketId)
        hasher.combine(timestamp)
    }
}



#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeCollectPaymentResult: FfiConverterRustBuffer {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> CollectPaymentResult {
        return
            try CollectPaymentResult(
                ticketId: FfiConverterString.read(from: &buf), 
                timestamp: FfiConverterTimestamp.read(from: &buf)
        )
    }

    public static func write(_ value: CollectPaymentResult, into buf: inout [UInt8]) {
        FfiConverterString.write(value.ticketId, into: &buf)
        FfiConverterTimestamp.write(value.timestamp, into: &buf)
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeCollectPaymentResult_lift(_ buf: RustBuffer) throws -> CollectPaymentResult {
    return try FfiConverterTypeCollectPaymentResult.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeCollectPaymentResult_lower(_ value: CollectPaymentResult) -> RustBuffer {
    return FfiConverterTypeCollectPaymentResult.lower(value)
}


public struct TransactionsResult {
    public var data: [Transaction]?
    public var ticketId: String
    public var timestamp: Date

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(data: [Transaction]?, ticketId: String, timestamp: Date) {
        self.data = data
        self.ticketId = ticketId
        self.timestamp = timestamp
    }
}

#if compiler(>=6)
extension TransactionsResult: Sendable {}
#endif


extension TransactionsResult: Equatable, Hashable {
    public static func ==(lhs: TransactionsResult, rhs: TransactionsResult) -> Bool {
        if lhs.data != rhs.data {
            return false
        }
        if lhs.ticketId != rhs.ticketId {
            return false
        }
        if lhs.timestamp != rhs.timestamp {
            return false
        }
        return true
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(data)
        hasher.combine(ticketId)
        hasher.combine(timestamp)
    }
}



#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeTransactionsResult: FfiConverterRustBuffer {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> TransactionsResult {
        return
            try TransactionsResult(
                data: FfiConverterOptionSequenceTypeTransaction.read(from: &buf), 
                ticketId: FfiConverterString.read(from: &buf), 
                timestamp: FfiConverterTimestamp.read(from: &buf)
        )
    }

    public static func write(_ value: TransactionsResult, into buf: inout [UInt8]) {
        FfiConverterOptionSequenceTypeTransaction.write(value.data, into: &buf)
        FfiConverterString.write(value.ticketId, into: &buf)
        FfiConverterTimestamp.write(value.timestamp, into: &buf)
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeTransactionsResult_lift(_ buf: RustBuffer) throws -> TransactionsResult {
    return try FfiConverterTypeTransactionsResult.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeTransactionsResult_lower(_ value: TransactionsResult) -> RustBuffer {
    return FfiConverterTypeTransactionsResult.lower(value)
}

// Note that we don't yet support `indirect` for enums.
// See https://github.com/mozilla/uniffi-rs/issues/396 for further discussion.

public enum AccountFilter {
    
    case ibanEq(value: String?
    )
    case ibanNotEq(value: String?
    )
    case numberEq(value: String?
    )
    case numberNotEq(value: String?
    )
    case bicEq(value: String?
    )
    case bicNotEq(value: String?
    )
    case bankCodeEq(value: String?
    )
    case bankCodeNotEq(value: String?
    )
    case currencyEq(value: String
    )
    case currencyNotEq(value: String
    )
    case nameEq(value: String?
    )
    case nameNotEq(value: String?
    )
    case displayNameEq(value: String?
    )
    case displayNameNotEq(value: String?
    )
    case ownerNameEq(value: String?
    )
    case ownerNameNotEq(value: String?
    )
    case productNameEq(value: String?
    )
    case productNameNotEq(value: String?
    )
    case statusEq(value: AccountStatus?
    )
    case statusNotEq(value: AccountStatus?
    )
    case typeEq(value: AccountType?
    )
    case typeNotEq(value: AccountType?
    )
    case all(filters: [AccountFilter]
    )
    case any(filters: [AccountFilter]
    )
    case supports(service: SupportedService
    )
}


#if compiler(>=6)
extension AccountFilter: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeAccountFilter: FfiConverterRustBuffer {
    typealias SwiftType = AccountFilter

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> AccountFilter {
        let variant: Int32 = try readInt(&buf)
        switch variant {
        
        case 1: return .ibanEq(value: try FfiConverterOptionString.read(from: &buf)
        )
        
        case 2: return .ibanNotEq(value: try FfiConverterOptionString.read(from: &buf)
        )
        
        case 3: return .numberEq(value: try FfiConverterOptionString.read(from: &buf)
        )
        
        case 4: return .numberNotEq(value: try FfiConverterOptionString.read(from: &buf)
        )
        
        case 5: return .bicEq(value: try FfiConverterOptionString.read(from: &buf)
        )
        
        case 6: return .bicNotEq(value: try FfiConverterOptionString.read(from: &buf)
        )
        
        case 7: return .bankCodeEq(value: try FfiConverterOptionString.read(from: &buf)
        )
        
        case 8: return .bankCodeNotEq(value: try FfiConverterOptionString.read(from: &buf)
        )
        
        case 9: return .currencyEq(value: try FfiConverterString.read(from: &buf)
        )
        
        case 10: return .currencyNotEq(value: try FfiConverterString.read(from: &buf)
        )
        
        case 11: return .nameEq(value: try FfiConverterOptionString.read(from: &buf)
        )
        
        case 12: return .nameNotEq(value: try FfiConverterOptionString.read(from: &buf)
        )
        
        case 13: return .displayNameEq(value: try FfiConverterOptionString.read(from: &buf)
        )
        
        case 14: return .displayNameNotEq(value: try FfiConverterOptionString.read(from: &buf)
        )
        
        case 15: return .ownerNameEq(value: try FfiConverterOptionString.read(from: &buf)
        )
        
        case 16: return .ownerNameNotEq(value: try FfiConverterOptionString.read(from: &buf)
        )
        
        case 17: return .productNameEq(value: try FfiConverterOptionString.read(from: &buf)
        )
        
        case 18: return .productNameNotEq(value: try FfiConverterOptionString.read(from: &buf)
        )
        
        case 19: return .statusEq(value: try FfiConverterOptionTypeAccountStatus.read(from: &buf)
        )
        
        case 20: return .statusNotEq(value: try FfiConverterOptionTypeAccountStatus.read(from: &buf)
        )
        
        case 21: return .typeEq(value: try FfiConverterOptionTypeAccountType.read(from: &buf)
        )
        
        case 22: return .typeNotEq(value: try FfiConverterOptionTypeAccountType.read(from: &buf)
        )
        
        case 23: return .all(filters: try FfiConverterSequenceTypeAccountFilter.read(from: &buf)
        )
        
        case 24: return .any(filters: try FfiConverterSequenceTypeAccountFilter.read(from: &buf)
        )
        
        case 25: return .supports(service: try FfiConverterTypeSupportedService.read(from: &buf)
        )
        
        default: throw UniffiInternalError.unexpectedEnumCase
        }
    }

    public static func write(_ value: AccountFilter, into buf: inout [UInt8]) {
        switch value {
        
        
        case let .ibanEq(value):
            writeInt(&buf, Int32(1))
            FfiConverterOptionString.write(value, into: &buf)
            
        
        case let .ibanNotEq(value):
            writeInt(&buf, Int32(2))
            FfiConverterOptionString.write(value, into: &buf)
            
        
        case let .numberEq(value):
            writeInt(&buf, Int32(3))
            FfiConverterOptionString.write(value, into: &buf)
            
        
        case let .numberNotEq(value):
            writeInt(&buf, Int32(4))
            FfiConverterOptionString.write(value, into: &buf)
            
        
        case let .bicEq(value):
            writeInt(&buf, Int32(5))
            FfiConverterOptionString.write(value, into: &buf)
            
        
        case let .bicNotEq(value):
            writeInt(&buf, Int32(6))
            FfiConverterOptionString.write(value, into: &buf)
            
        
        case let .bankCodeEq(value):
            writeInt(&buf, Int32(7))
            FfiConverterOptionString.write(value, into: &buf)
            
        
        case let .bankCodeNotEq(value):
            writeInt(&buf, Int32(8))
            FfiConverterOptionString.write(value, into: &buf)
            
        
        case let .currencyEq(value):
            writeInt(&buf, Int32(9))
            FfiConverterString.write(value, into: &buf)
            
        
        case let .currencyNotEq(value):
            writeInt(&buf, Int32(10))
            FfiConverterString.write(value, into: &buf)
            
        
        case let .nameEq(value):
            writeInt(&buf, Int32(11))
            FfiConverterOptionString.write(value, into: &buf)
            
        
        case let .nameNotEq(value):
            writeInt(&buf, Int32(12))
            FfiConverterOptionString.write(value, into: &buf)
            
        
        case let .displayNameEq(value):
            writeInt(&buf, Int32(13))
            FfiConverterOptionString.write(value, into: &buf)
            
        
        case let .displayNameNotEq(value):
            writeInt(&buf, Int32(14))
            FfiConverterOptionString.write(value, into: &buf)
            
        
        case let .ownerNameEq(value):
            writeInt(&buf, Int32(15))
            FfiConverterOptionString.write(value, into: &buf)
            
        
        case let .ownerNameNotEq(value):
            writeInt(&buf, Int32(16))
            FfiConverterOptionString.write(value, into: &buf)
            
        
        case let .productNameEq(value):
            writeInt(&buf, Int32(17))
            FfiConverterOptionString.write(value, into: &buf)
            
        
        case let .productNameNotEq(value):
            writeInt(&buf, Int32(18))
            FfiConverterOptionString.write(value, into: &buf)
            
        
        case let .statusEq(value):
            writeInt(&buf, Int32(19))
            FfiConverterOptionTypeAccountStatus.write(value, into: &buf)
            
        
        case let .statusNotEq(value):
            writeInt(&buf, Int32(20))
            FfiConverterOptionTypeAccountStatus.write(value, into: &buf)
            
        
        case let .typeEq(value):
            writeInt(&buf, Int32(21))
            FfiConverterOptionTypeAccountType.write(value, into: &buf)
            
        
        case let .typeNotEq(value):
            writeInt(&buf, Int32(22))
            FfiConverterOptionTypeAccountType.write(value, into: &buf)
            
        
        case let .all(filters):
            writeInt(&buf, Int32(23))
            FfiConverterSequenceTypeAccountFilter.write(filters, into: &buf)
            
        
        case let .any(filters):
            writeInt(&buf, Int32(24))
            FfiConverterSequenceTypeAccountFilter.write(filters, into: &buf)
            
        
        case let .supports(service):
            writeInt(&buf, Int32(25))
            FfiConverterTypeSupportedService.write(service, into: &buf)
            
        }
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAccountFilter_lift(_ buf: RustBuffer) throws -> AccountFilter {
    return try FfiConverterTypeAccountFilter.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAccountFilter_lower(_ value: AccountFilter) -> RustBuffer {
    return FfiConverterTypeAccountFilter.lower(value)
}


extension AccountFilter: Equatable, Hashable {}



// Note that we don't yet support `indirect` for enums.
// See https://github.com/mozilla/uniffi-rs/issues/396 for further discussion.
/**
 * Response from YAXI Open Banking services.
 *
 * The response either carries an authenticated result
 * or an interrupt (i.e. a dialog or redirect for the user).
 */

public enum AccountsResponse {
    
    case result(result: AuthenticatedAccountsResult, session: Session?, connectionData: ConnectionData?
    )
    case dialog(context: DialogContext?, message: String?, image: Image?, input: DialogInput
    )
    case redirect(url: Url, context: ConfirmationContext
    )
    case redirectHandle(handle: String, context: ConfirmationContext
    )
}


#if compiler(>=6)
extension AccountsResponse: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeAccountsResponse: FfiConverterRustBuffer {
    typealias SwiftType = AccountsResponse

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> AccountsResponse {
        let variant: Int32 = try readInt(&buf)
        switch variant {
        
        case 1: return .result(result: try FfiConverterTypeAuthenticatedAccountsResult.read(from: &buf), session: try FfiConverterOptionTypeSession.read(from: &buf), connectionData: try FfiConverterOptionTypeConnectionData.read(from: &buf)
        )
        
        case 2: return .dialog(context: try FfiConverterOptionTypeDialogContext.read(from: &buf), message: try FfiConverterOptionString.read(from: &buf), image: try FfiConverterOptionTypeImage.read(from: &buf), input: try FfiConverterTypeDialogInput.read(from: &buf)
        )
        
        case 3: return .redirect(url: try FfiConverterTypeUrl.read(from: &buf), context: try FfiConverterTypeConfirmationContext.read(from: &buf)
        )
        
        case 4: return .redirectHandle(handle: try FfiConverterString.read(from: &buf), context: try FfiConverterTypeConfirmationContext.read(from: &buf)
        )
        
        default: throw UniffiInternalError.unexpectedEnumCase
        }
    }

    public static func write(_ value: AccountsResponse, into buf: inout [UInt8]) {
        switch value {
        
        
        case let .result(result,session,connectionData):
            writeInt(&buf, Int32(1))
            FfiConverterTypeAuthenticatedAccountsResult.write(result, into: &buf)
            FfiConverterOptionTypeSession.write(session, into: &buf)
            FfiConverterOptionTypeConnectionData.write(connectionData, into: &buf)
            
        
        case let .dialog(context,message,image,input):
            writeInt(&buf, Int32(2))
            FfiConverterOptionTypeDialogContext.write(context, into: &buf)
            FfiConverterOptionString.write(message, into: &buf)
            FfiConverterOptionTypeImage.write(image, into: &buf)
            FfiConverterTypeDialogInput.write(input, into: &buf)
            
        
        case let .redirect(url,context):
            writeInt(&buf, Int32(3))
            FfiConverterTypeUrl.write(url, into: &buf)
            FfiConverterTypeConfirmationContext.write(context, into: &buf)
            
        
        case let .redirectHandle(handle,context):
            writeInt(&buf, Int32(4))
            FfiConverterString.write(handle, into: &buf)
            FfiConverterTypeConfirmationContext.write(context, into: &buf)
            
        }
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAccountsResponse_lift(_ buf: RustBuffer) throws -> AccountsResponse {
    return try FfiConverterTypeAccountsResponse.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAccountsResponse_lower(_ value: AccountsResponse) -> RustBuffer {
    return FfiConverterTypeAccountsResponse.lower(value)
}




// Note that we don't yet support `indirect` for enums.
// See https://github.com/mozilla/uniffi-rs/issues/396 for further discussion.
/**
 * Response from YAXI Open Banking services.
 *
 * The response either carries an authenticated result
 * or an interrupt (i.e. a dialog or redirect for the user).
 */

public enum CollectPaymentResponse {
    
    case result(result: AuthenticatedCollectPaymentResult, session: Session?, connectionData: ConnectionData?
    )
    case dialog(context: DialogContext?, message: String?, image: Image?, input: DialogInput
    )
    case redirect(url: Url, context: ConfirmationContext
    )
    case redirectHandle(handle: String, context: ConfirmationContext
    )
}


#if compiler(>=6)
extension CollectPaymentResponse: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeCollectPaymentResponse: FfiConverterRustBuffer {
    typealias SwiftType = CollectPaymentResponse

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> CollectPaymentResponse {
        let variant: Int32 = try readInt(&buf)
        switch variant {
        
        case 1: return .result(result: try FfiConverterTypeAuthenticatedCollectPaymentResult.read(from: &buf), session: try FfiConverterOptionTypeSession.read(from: &buf), connectionData: try FfiConverterOptionTypeConnectionData.read(from: &buf)
        )
        
        case 2: return .dialog(context: try FfiConverterOptionTypeDialogContext.read(from: &buf), message: try FfiConverterOptionString.read(from: &buf), image: try FfiConverterOptionTypeImage.read(from: &buf), input: try FfiConverterTypeDialogInput.read(from: &buf)
        )
        
        case 3: return .redirect(url: try FfiConverterTypeUrl.read(from: &buf), context: try FfiConverterTypeConfirmationContext.read(from: &buf)
        )
        
        case 4: return .redirectHandle(handle: try FfiConverterString.read(from: &buf), context: try FfiConverterTypeConfirmationContext.read(from: &buf)
        )
        
        default: throw UniffiInternalError.unexpectedEnumCase
        }
    }

    public static func write(_ value: CollectPaymentResponse, into buf: inout [UInt8]) {
        switch value {
        
        
        case let .result(result,session,connectionData):
            writeInt(&buf, Int32(1))
            FfiConverterTypeAuthenticatedCollectPaymentResult.write(result, into: &buf)
            FfiConverterOptionTypeSession.write(session, into: &buf)
            FfiConverterOptionTypeConnectionData.write(connectionData, into: &buf)
            
        
        case let .dialog(context,message,image,input):
            writeInt(&buf, Int32(2))
            FfiConverterOptionTypeDialogContext.write(context, into: &buf)
            FfiConverterOptionString.write(message, into: &buf)
            FfiConverterOptionTypeImage.write(image, into: &buf)
            FfiConverterTypeDialogInput.write(input, into: &buf)
            
        
        case let .redirect(url,context):
            writeInt(&buf, Int32(3))
            FfiConverterTypeUrl.write(url, into: &buf)
            FfiConverterTypeConfirmationContext.write(context, into: &buf)
            
        
        case let .redirectHandle(handle,context):
            writeInt(&buf, Int32(4))
            FfiConverterString.write(handle, into: &buf)
            FfiConverterTypeConfirmationContext.write(context, into: &buf)
            
        }
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeCollectPaymentResponse_lift(_ buf: RustBuffer) throws -> CollectPaymentResponse {
    return try FfiConverterTypeCollectPaymentResponse.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeCollectPaymentResponse_lower(_ value: CollectPaymentResponse) -> RustBuffer {
    return FfiConverterTypeCollectPaymentResponse.lower(value)
}




// Note that we don't yet support `indirect` for enums.
// See https://github.com/mozilla/uniffi-rs/issues/396 for further discussion.
/**
 * Data defining the interactive part of a user dialog.
 */

public enum DialogInput {
    
    /**
     * Just a primary action to confirm the dialog.
     */
    case confirmation(context: ConfirmationContext
    )
    /**
     * A selection of options the user can choose from.
     *
     * Options are meant to be rendered e.g. as radio buttons where the user must select exactly
     * one to for a confirmation button to get enabled. Another example for an implementation is
     * one button per option that immediately confirms the selection.
     */
    case selection(options: [DialogOption], context: InputContext
    )
    /**
     * An input field.
     *
     * `type_`, `min_length` and `max_length` may be used for showing hints or dedicated keyboard
     * layouts and for applying input restrictions or validation.
     *
     * `secrecy_level` indicates if the input should be masked.
     */
    case field(type: InputType, secrecyLevel: SecrecyLevel, minLength: UInt32?, maxLength: UInt32?, context: InputContext
    )
}


#if compiler(>=6)
extension DialogInput: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeDialogInput: FfiConverterRustBuffer {
    typealias SwiftType = DialogInput

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> DialogInput {
        let variant: Int32 = try readInt(&buf)
        switch variant {
        
        case 1: return .confirmation(context: try FfiConverterTypeConfirmationContext.read(from: &buf)
        )
        
        case 2: return .selection(options: try FfiConverterSequenceTypeDialogOption.read(from: &buf), context: try FfiConverterTypeInputContext.read(from: &buf)
        )
        
        case 3: return .field(type: try FfiConverterTypeInputType.read(from: &buf), secrecyLevel: try FfiConverterTypeSecrecyLevel.read(from: &buf), minLength: try FfiConverterOptionUInt32.read(from: &buf), maxLength: try FfiConverterOptionUInt32.read(from: &buf), context: try FfiConverterTypeInputContext.read(from: &buf)
        )
        
        default: throw UniffiInternalError.unexpectedEnumCase
        }
    }

    public static func write(_ value: DialogInput, into buf: inout [UInt8]) {
        switch value {
        
        
        case let .confirmation(context):
            writeInt(&buf, Int32(1))
            FfiConverterTypeConfirmationContext.write(context, into: &buf)
            
        
        case let .selection(options,context):
            writeInt(&buf, Int32(2))
            FfiConverterSequenceTypeDialogOption.write(options, into: &buf)
            FfiConverterTypeInputContext.write(context, into: &buf)
            
        
        case let .field(type,secrecyLevel,minLength,maxLength,context):
            writeInt(&buf, Int32(3))
            FfiConverterTypeInputType.write(type, into: &buf)
            FfiConverterTypeSecrecyLevel.write(secrecyLevel, into: &buf)
            FfiConverterOptionUInt32.write(minLength, into: &buf)
            FfiConverterOptionUInt32.write(maxLength, into: &buf)
            FfiConverterTypeInputContext.write(context, into: &buf)
            
        }
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeDialogInput_lift(_ buf: RustBuffer) throws -> DialogInput {
    return try FfiConverterTypeDialogInput.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeDialogInput_lower(_ value: DialogInput) -> RustBuffer {
    return FfiConverterTypeDialogInput.lower(value)
}


extension DialogInput: Equatable, Hashable {}




public enum RoutexClientError {

    
    
    case InvalidRedirectUri
    case RequestError(error: String
    )
    case UnexpectedError(userMessage: String?
    )
    case Canceled
    case InvalidCredentials(userMessage: String?
    )
    case ServiceBlocked(userMessage: String?
    )
    case Unauthorized(userMessage: String?
    )
    case ConsentExpired(userMessage: String?
    )
    case AccessExceeded(userMessage: String?
    )
    case PeriodOutOfBounds(userMessage: String?
    )
    case UnsupportedProduct
    case PaymentFailed(code: PaymentErrorCode?, userMessage: String?
    )
    case UnexpectedValue(error: String
    )
    case TicketError(error: String, code: TicketErrorCode
    )
    case ResponseError(response: String
    )
    case NotFound
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeRoutexClientError: FfiConverterRustBuffer {
    typealias SwiftType = RoutexClientError

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> RoutexClientError {
        let variant: Int32 = try readInt(&buf)
        switch variant {

        

        
        case 1: return .InvalidRedirectUri
        case 2: return .RequestError(
            error: try FfiConverterString.read(from: &buf)
            )
        case 3: return .UnexpectedError(
            userMessage: try FfiConverterOptionString.read(from: &buf)
            )
        case 4: return .Canceled
        case 5: return .InvalidCredentials(
            userMessage: try FfiConverterOptionString.read(from: &buf)
            )
        case 6: return .ServiceBlocked(
            userMessage: try FfiConverterOptionString.read(from: &buf)
            )
        case 7: return .Unauthorized(
            userMessage: try FfiConverterOptionString.read(from: &buf)
            )
        case 8: return .ConsentExpired(
            userMessage: try FfiConverterOptionString.read(from: &buf)
            )
        case 9: return .AccessExceeded(
            userMessage: try FfiConverterOptionString.read(from: &buf)
            )
        case 10: return .PeriodOutOfBounds(
            userMessage: try FfiConverterOptionString.read(from: &buf)
            )
        case 11: return .UnsupportedProduct
        case 12: return .PaymentFailed(
            code: try FfiConverterOptionTypePaymentErrorCode.read(from: &buf), 
            userMessage: try FfiConverterOptionString.read(from: &buf)
            )
        case 13: return .UnexpectedValue(
            error: try FfiConverterString.read(from: &buf)
            )
        case 14: return .TicketError(
            error: try FfiConverterString.read(from: &buf), 
            code: try FfiConverterTypeTicketErrorCode.read(from: &buf)
            )
        case 15: return .ResponseError(
            response: try FfiConverterString.read(from: &buf)
            )
        case 16: return .NotFound

         default: throw UniffiInternalError.unexpectedEnumCase
        }
    }

    public static func write(_ value: RoutexClientError, into buf: inout [UInt8]) {
        switch value {

        

        
        
        case .InvalidRedirectUri:
            writeInt(&buf, Int32(1))
        
        
        case let .RequestError(error):
            writeInt(&buf, Int32(2))
            FfiConverterString.write(error, into: &buf)
            
        
        case let .UnexpectedError(userMessage):
            writeInt(&buf, Int32(3))
            FfiConverterOptionString.write(userMessage, into: &buf)
            
        
        case .Canceled:
            writeInt(&buf, Int32(4))
        
        
        case let .InvalidCredentials(userMessage):
            writeInt(&buf, Int32(5))
            FfiConverterOptionString.write(userMessage, into: &buf)
            
        
        case let .ServiceBlocked(userMessage):
            writeInt(&buf, Int32(6))
            FfiConverterOptionString.write(userMessage, into: &buf)
            
        
        case let .Unauthorized(userMessage):
            writeInt(&buf, Int32(7))
            FfiConverterOptionString.write(userMessage, into: &buf)
            
        
        case let .ConsentExpired(userMessage):
            writeInt(&buf, Int32(8))
            FfiConverterOptionString.write(userMessage, into: &buf)
            
        
        case let .AccessExceeded(userMessage):
            writeInt(&buf, Int32(9))
            FfiConverterOptionString.write(userMessage, into: &buf)
            
        
        case let .PeriodOutOfBounds(userMessage):
            writeInt(&buf, Int32(10))
            FfiConverterOptionString.write(userMessage, into: &buf)
            
        
        case .UnsupportedProduct:
            writeInt(&buf, Int32(11))
        
        
        case let .PaymentFailed(code,userMessage):
            writeInt(&buf, Int32(12))
            FfiConverterOptionTypePaymentErrorCode.write(code, into: &buf)
            FfiConverterOptionString.write(userMessage, into: &buf)
            
        
        case let .UnexpectedValue(error):
            writeInt(&buf, Int32(13))
            FfiConverterString.write(error, into: &buf)
            
        
        case let .TicketError(error,code):
            writeInt(&buf, Int32(14))
            FfiConverterString.write(error, into: &buf)
            FfiConverterTypeTicketErrorCode.write(code, into: &buf)
            
        
        case let .ResponseError(response):
            writeInt(&buf, Int32(15))
            FfiConverterString.write(response, into: &buf)
            
        
        case .NotFound:
            writeInt(&buf, Int32(16))
        
        }
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeRoutexClientError_lift(_ buf: RustBuffer) throws -> RoutexClientError {
    return try FfiConverterTypeRoutexClientError.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeRoutexClientError_lower(_ value: RoutexClientError) -> RustBuffer {
    return FfiConverterTypeRoutexClientError.lower(value)
}


extension RoutexClientError: Equatable, Hashable {}



extension RoutexClientError: Foundation.LocalizedError {
    public var errorDescription: String? {
        String(reflecting: self)
    }
}


// Note that we don't yet support `indirect` for enums.
// See https://github.com/mozilla/uniffi-rs/issues/396 for further discussion.
/**
 * Filters for the connection lookup
 *
 * String filters look for the given value anywhere in the related field, case-insensitive.
 */

public enum SearchFilter {
    
    /**
     * List of [`ConnectionType`]s to consider.
     */
    case types(types: [ConnectionType]
    )
    /**
     * List of [`CountryCode`]s to consider.
     */
    case countries(countries: [CountryCode]
    )
    /**
     * String filter for the provider / product name or any alias.
     */
    case name(name: String
    )
    /**
     * String filter for the BIC.
     */
    case bic(bic: String
    )
    /**
     * String filter for the (national) bank code.
     */
    case bankCode(bankCode: String
    )
    /**
     * String filter for any of those fields.
     */
    case term(term: String
    )
}


#if compiler(>=6)
extension SearchFilter: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeSearchFilter: FfiConverterRustBuffer {
    typealias SwiftType = SearchFilter

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> SearchFilter {
        let variant: Int32 = try readInt(&buf)
        switch variant {
        
        case 1: return .types(types: try FfiConverterSequenceTypeConnectionType.read(from: &buf)
        )
        
        case 2: return .countries(countries: try FfiConverterSequenceTypeCountryCode.read(from: &buf)
        )
        
        case 3: return .name(name: try FfiConverterString.read(from: &buf)
        )
        
        case 4: return .bic(bic: try FfiConverterString.read(from: &buf)
        )
        
        case 5: return .bankCode(bankCode: try FfiConverterString.read(from: &buf)
        )
        
        case 6: return .term(term: try FfiConverterString.read(from: &buf)
        )
        
        default: throw UniffiInternalError.unexpectedEnumCase
        }
    }

    public static func write(_ value: SearchFilter, into buf: inout [UInt8]) {
        switch value {
        
        
        case let .types(types):
            writeInt(&buf, Int32(1))
            FfiConverterSequenceTypeConnectionType.write(types, into: &buf)
            
        
        case let .countries(countries):
            writeInt(&buf, Int32(2))
            FfiConverterSequenceTypeCountryCode.write(countries, into: &buf)
            
        
        case let .name(name):
            writeInt(&buf, Int32(3))
            FfiConverterString.write(name, into: &buf)
            
        
        case let .bic(bic):
            writeInt(&buf, Int32(4))
            FfiConverterString.write(bic, into: &buf)
            
        
        case let .bankCode(bankCode):
            writeInt(&buf, Int32(5))
            FfiConverterString.write(bankCode, into: &buf)
            
        
        case let .term(term):
            writeInt(&buf, Int32(6))
            FfiConverterString.write(term, into: &buf)
            
        }
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeSearchFilter_lift(_ buf: RustBuffer) throws -> SearchFilter {
    return try FfiConverterTypeSearchFilter.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeSearchFilter_lower(_ value: SearchFilter) -> RustBuffer {
    return FfiConverterTypeSearchFilter.lower(value)
}


extension SearchFilter: Equatable, Hashable {}



// Note that we don't yet support `indirect` for enums.
// See https://github.com/mozilla/uniffi-rs/issues/396 for further discussion.
/**
 * Response from YAXI Open Banking services.
 *
 * The response either carries an authenticated result
 * or an interrupt (i.e. a dialog or redirect for the user).
 */

public enum TransactionsResponse {
    
    case result(result: AuthenticatedTransactionsResult, session: Session?, connectionData: ConnectionData?
    )
    case dialog(context: DialogContext?, message: String?, image: Image?, input: DialogInput
    )
    case redirect(url: Url, context: ConfirmationContext
    )
    case redirectHandle(handle: String, context: ConfirmationContext
    )
}


#if compiler(>=6)
extension TransactionsResponse: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeTransactionsResponse: FfiConverterRustBuffer {
    typealias SwiftType = TransactionsResponse

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> TransactionsResponse {
        let variant: Int32 = try readInt(&buf)
        switch variant {
        
        case 1: return .result(result: try FfiConverterTypeAuthenticatedTransactionsResult.read(from: &buf), session: try FfiConverterOptionTypeSession.read(from: &buf), connectionData: try FfiConverterOptionTypeConnectionData.read(from: &buf)
        )
        
        case 2: return .dialog(context: try FfiConverterOptionTypeDialogContext.read(from: &buf), message: try FfiConverterOptionString.read(from: &buf), image: try FfiConverterOptionTypeImage.read(from: &buf), input: try FfiConverterTypeDialogInput.read(from: &buf)
        )
        
        case 3: return .redirect(url: try FfiConverterTypeUrl.read(from: &buf), context: try FfiConverterTypeConfirmationContext.read(from: &buf)
        )
        
        case 4: return .redirectHandle(handle: try FfiConverterString.read(from: &buf), context: try FfiConverterTypeConfirmationContext.read(from: &buf)
        )
        
        default: throw UniffiInternalError.unexpectedEnumCase
        }
    }

    public static func write(_ value: TransactionsResponse, into buf: inout [UInt8]) {
        switch value {
        
        
        case let .result(result,session,connectionData):
            writeInt(&buf, Int32(1))
            FfiConverterTypeAuthenticatedTransactionsResult.write(result, into: &buf)
            FfiConverterOptionTypeSession.write(session, into: &buf)
            FfiConverterOptionTypeConnectionData.write(connectionData, into: &buf)
            
        
        case let .dialog(context,message,image,input):
            writeInt(&buf, Int32(2))
            FfiConverterOptionTypeDialogContext.write(context, into: &buf)
            FfiConverterOptionString.write(message, into: &buf)
            FfiConverterOptionTypeImage.write(image, into: &buf)
            FfiConverterTypeDialogInput.write(input, into: &buf)
            
        
        case let .redirect(url,context):
            writeInt(&buf, Int32(3))
            FfiConverterTypeUrl.write(url, into: &buf)
            FfiConverterTypeConfirmationContext.write(context, into: &buf)
            
        
        case let .redirectHandle(handle,context):
            writeInt(&buf, Int32(4))
            FfiConverterString.write(handle, into: &buf)
            FfiConverterTypeConfirmationContext.write(context, into: &buf)
            
        }
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeTransactionsResponse_lift(_ buf: RustBuffer) throws -> TransactionsResponse {
    return try FfiConverterTypeTransactionsResponse.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeTransactionsResponse_lower(_ value: TransactionsResponse) -> RustBuffer {
    return FfiConverterTypeTransactionsResponse.lower(value)
}




#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterOptionUInt32: FfiConverterRustBuffer {
    typealias SwiftType = UInt32?

    public static func write(_ value: SwiftType, into buf: inout [UInt8]) {
        guard let value = value else {
            writeInt(&buf, Int8(0))
            return
        }
        writeInt(&buf, Int8(1))
        FfiConverterUInt32.write(value, into: &buf)
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> SwiftType {
        switch try readInt(&buf) as Int8 {
        case 0: return nil
        case 1: return try FfiConverterUInt32.read(from: &buf)
        default: throw UniffiInternalError.unexpectedOptionalTag
        }
    }
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterOptionString: FfiConverterRustBuffer {
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

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterOptionData: FfiConverterRustBuffer {
    typealias SwiftType = Data?

    public static func write(_ value: SwiftType, into buf: inout [UInt8]) {
        guard let value = value else {
            writeInt(&buf, Int8(0))
            return
        }
        writeInt(&buf, Int8(1))
        FfiConverterData.write(value, into: &buf)
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> SwiftType {
        switch try readInt(&buf) as Int8 {
        case 0: return nil
        case 1: return try FfiConverterData.read(from: &buf)
        default: throw UniffiInternalError.unexpectedOptionalTag
        }
    }
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterOptionTypeImage: FfiConverterRustBuffer {
    typealias SwiftType = Image?

    public static func write(_ value: SwiftType, into buf: inout [UInt8]) {
        guard let value = value else {
            writeInt(&buf, Int8(0))
            return
        }
        writeInt(&buf, Int8(1))
        FfiConverterTypeImage.write(value, into: &buf)
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> SwiftType {
        switch try readInt(&buf) as Int8 {
        case 0: return nil
        case 1: return try FfiConverterTypeImage.read(from: &buf)
        default: throw UniffiInternalError.unexpectedOptionalTag
        }
    }
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterOptionTypeAccountReference: FfiConverterRustBuffer {
    typealias SwiftType = AccountReference?

    public static func write(_ value: SwiftType, into buf: inout [UInt8]) {
        guard let value = value else {
            writeInt(&buf, Int8(0))
            return
        }
        writeInt(&buf, Int8(1))
        FfiConverterTypeAccountReference.write(value, into: &buf)
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> SwiftType {
        switch try readInt(&buf) as Int8 {
        case 0: return nil
        case 1: return try FfiConverterTypeAccountReference.read(from: &buf)
        default: throw UniffiInternalError.unexpectedOptionalTag
        }
    }
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterOptionTypeAccountStatus: FfiConverterRustBuffer {
    typealias SwiftType = AccountStatus?

    public static func write(_ value: SwiftType, into buf: inout [UInt8]) {
        guard let value = value else {
            writeInt(&buf, Int8(0))
            return
        }
        writeInt(&buf, Int8(1))
        FfiConverterTypeAccountStatus.write(value, into: &buf)
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> SwiftType {
        switch try readInt(&buf) as Int8 {
        case 0: return nil
        case 1: return try FfiConverterTypeAccountStatus.read(from: &buf)
        default: throw UniffiInternalError.unexpectedOptionalTag
        }
    }
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterOptionTypeAccountType: FfiConverterRustBuffer {
    typealias SwiftType = AccountType?

    public static func write(_ value: SwiftType, into buf: inout [UInt8]) {
        guard let value = value else {
            writeInt(&buf, Int8(0))
            return
        }
        writeInt(&buf, Int8(1))
        FfiConverterTypeAccountType.write(value, into: &buf)
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> SwiftType {
        switch try readInt(&buf) as Int8 {
        case 0: return nil
        case 1: return try FfiConverterTypeAccountType.read(from: &buf)
        default: throw UniffiInternalError.unexpectedOptionalTag
        }
    }
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterOptionTypeDialogContext: FfiConverterRustBuffer {
    typealias SwiftType = DialogContext?

    public static func write(_ value: SwiftType, into buf: inout [UInt8]) {
        guard let value = value else {
            writeInt(&buf, Int8(0))
            return
        }
        writeInt(&buf, Int8(1))
        FfiConverterTypeDialogContext.write(value, into: &buf)
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> SwiftType {
        switch try readInt(&buf) as Int8 {
        case 0: return nil
        case 1: return try FfiConverterTypeDialogContext.read(from: &buf)
        default: throw UniffiInternalError.unexpectedOptionalTag
        }
    }
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterOptionTypePaymentErrorCode: FfiConverterRustBuffer {
    typealias SwiftType = PaymentErrorCode?

    public static func write(_ value: SwiftType, into buf: inout [UInt8]) {
        guard let value = value else {
            writeInt(&buf, Int8(0))
            return
        }
        writeInt(&buf, Int8(1))
        FfiConverterTypePaymentErrorCode.write(value, into: &buf)
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> SwiftType {
        switch try readInt(&buf) as Int8 {
        case 0: return nil
        case 1: return try FfiConverterTypePaymentErrorCode.read(from: &buf)
        default: throw UniffiInternalError.unexpectedOptionalTag
        }
    }
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterOptionTypeAccountFilter: FfiConverterRustBuffer {
    typealias SwiftType = AccountFilter?

    public static func write(_ value: SwiftType, into buf: inout [UInt8]) {
        guard let value = value else {
            writeInt(&buf, Int8(0))
            return
        }
        writeInt(&buf, Int8(1))
        FfiConverterTypeAccountFilter.write(value, into: &buf)
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> SwiftType {
        switch try readInt(&buf) as Int8 {
        case 0: return nil
        case 1: return try FfiConverterTypeAccountFilter.read(from: &buf)
        default: throw UniffiInternalError.unexpectedOptionalTag
        }
    }
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterOptionSequenceTypeTransaction: FfiConverterRustBuffer {
    typealias SwiftType = [Transaction]?

    public static func write(_ value: SwiftType, into buf: inout [UInt8]) {
        guard let value = value else {
            writeInt(&buf, Int8(0))
            return
        }
        writeInt(&buf, Int8(1))
        FfiConverterSequenceTypeTransaction.write(value, into: &buf)
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> SwiftType {
        switch try readInt(&buf) as Int8 {
        case 0: return nil
        case 1: return try FfiConverterSequenceTypeTransaction.read(from: &buf)
        default: throw UniffiInternalError.unexpectedOptionalTag
        }
    }
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterOptionTypeConnectionData: FfiConverterRustBuffer {
    typealias SwiftType = ConnectionData?

    public static func write(_ value: SwiftType, into buf: inout [UInt8]) {
        guard let value = value else {
            writeInt(&buf, Int8(0))
            return
        }
        writeInt(&buf, Int8(1))
        FfiConverterTypeConnectionData.write(value, into: &buf)
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> SwiftType {
        switch try readInt(&buf) as Int8 {
        case 0: return nil
        case 1: return try FfiConverterTypeConnectionData.read(from: &buf)
        default: throw UniffiInternalError.unexpectedOptionalTag
        }
    }
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterOptionTypeSession: FfiConverterRustBuffer {
    typealias SwiftType = Session?

    public static func write(_ value: SwiftType, into buf: inout [UInt8]) {
        guard let value = value else {
            writeInt(&buf, Int8(0))
            return
        }
        writeInt(&buf, Int8(1))
        FfiConverterTypeSession.write(value, into: &buf)
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> SwiftType {
        switch try readInt(&buf) as Int8 {
        case 0: return nil
        case 1: return try FfiConverterTypeSession.read(from: &buf)
        default: throw UniffiInternalError.unexpectedOptionalTag
        }
    }
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterSequenceTypeDialogOption: FfiConverterRustBuffer {
    typealias SwiftType = [DialogOption]

    public static func write(_ value: [DialogOption], into buf: inout [UInt8]) {
        let len = Int32(value.count)
        writeInt(&buf, len)
        for item in value {
            FfiConverterTypeDialogOption.write(item, into: &buf)
        }
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> [DialogOption] {
        let len: Int32 = try readInt(&buf)
        var seq = [DialogOption]()
        seq.reserveCapacity(Int(len))
        for _ in 0 ..< len {
            seq.append(try FfiConverterTypeDialogOption.read(from: &buf))
        }
        return seq
    }
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterSequenceTypeAccount: FfiConverterRustBuffer {
    typealias SwiftType = [Account]

    public static func write(_ value: [Account], into buf: inout [UInt8]) {
        let len = Int32(value.count)
        writeInt(&buf, len)
        for item in value {
            FfiConverterTypeAccount.write(item, into: &buf)
        }
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> [Account] {
        let len: Int32 = try readInt(&buf)
        var seq = [Account]()
        seq.reserveCapacity(Int(len))
        for _ in 0 ..< len {
            seq.append(try FfiConverterTypeAccount.read(from: &buf))
        }
        return seq
    }
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterSequenceTypeConnectionInfo: FfiConverterRustBuffer {
    typealias SwiftType = [ConnectionInfo]

    public static func write(_ value: [ConnectionInfo], into buf: inout [UInt8]) {
        let len = Int32(value.count)
        writeInt(&buf, len)
        for item in value {
            FfiConverterTypeConnectionInfo.write(item, into: &buf)
        }
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> [ConnectionInfo] {
        let len: Int32 = try readInt(&buf)
        var seq = [ConnectionInfo]()
        seq.reserveCapacity(Int(len))
        for _ in 0 ..< len {
            seq.append(try FfiConverterTypeConnectionInfo.read(from: &buf))
        }
        return seq
    }
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterSequenceTypeTransaction: FfiConverterRustBuffer {
    typealias SwiftType = [Transaction]

    public static func write(_ value: [Transaction], into buf: inout [UInt8]) {
        let len = Int32(value.count)
        writeInt(&buf, len)
        for item in value {
            FfiConverterTypeTransaction.write(item, into: &buf)
        }
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> [Transaction] {
        let len: Int32 = try readInt(&buf)
        var seq = [Transaction]()
        seq.reserveCapacity(Int(len))
        for _ in 0 ..< len {
            seq.append(try FfiConverterTypeTransaction.read(from: &buf))
        }
        return seq
    }
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterSequenceTypeAccountField: FfiConverterRustBuffer {
    typealias SwiftType = [AccountField]

    public static func write(_ value: [AccountField], into buf: inout [UInt8]) {
        let len = Int32(value.count)
        writeInt(&buf, len)
        for item in value {
            FfiConverterTypeAccountField.write(item, into: &buf)
        }
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> [AccountField] {
        let len: Int32 = try readInt(&buf)
        var seq = [AccountField]()
        seq.reserveCapacity(Int(len))
        for _ in 0 ..< len {
            seq.append(try FfiConverterTypeAccountField.read(from: &buf))
        }
        return seq
    }
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterSequenceTypeConnectionType: FfiConverterRustBuffer {
    typealias SwiftType = [ConnectionType]

    public static func write(_ value: [ConnectionType], into buf: inout [UInt8]) {
        let len = Int32(value.count)
        writeInt(&buf, len)
        for item in value {
            FfiConverterTypeConnectionType.write(item, into: &buf)
        }
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> [ConnectionType] {
        let len: Int32 = try readInt(&buf)
        var seq = [ConnectionType]()
        seq.reserveCapacity(Int(len))
        for _ in 0 ..< len {
            seq.append(try FfiConverterTypeConnectionType.read(from: &buf))
        }
        return seq
    }
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterSequenceTypeAccountFilter: FfiConverterRustBuffer {
    typealias SwiftType = [AccountFilter]

    public static func write(_ value: [AccountFilter], into buf: inout [UInt8]) {
        let len = Int32(value.count)
        writeInt(&buf, len)
        for item in value {
            FfiConverterTypeAccountFilter.write(item, into: &buf)
        }
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> [AccountFilter] {
        let len: Int32 = try readInt(&buf)
        var seq = [AccountFilter]()
        seq.reserveCapacity(Int(len))
        for _ in 0 ..< len {
            seq.append(try FfiConverterTypeAccountFilter.read(from: &buf))
        }
        return seq
    }
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterSequenceTypeSearchFilter: FfiConverterRustBuffer {
    typealias SwiftType = [SearchFilter]

    public static func write(_ value: [SearchFilter], into buf: inout [UInt8]) {
        let len = Int32(value.count)
        writeInt(&buf, len)
        for item in value {
            FfiConverterTypeSearchFilter.write(item, into: &buf)
        }
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> [SearchFilter] {
        let len: Int32 = try readInt(&buf)
        var seq = [SearchFilter]()
        seq.reserveCapacity(Int(len))
        for _ in 0 ..< len {
            seq.append(try FfiConverterTypeSearchFilter.read(from: &buf))
        }
        return seq
    }
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterSequenceTypeCountryCode: FfiConverterRustBuffer {
    typealias SwiftType = [CountryCode]

    public static func write(_ value: [CountryCode], into buf: inout [UInt8]) {
        let len = Int32(value.count)
        writeInt(&buf, len)
        for item in value {
            FfiConverterTypeCountryCode.write(item, into: &buf)
        }
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> [CountryCode] {
        let len: Int32 = try readInt(&buf)
        var seq = [CountryCode]()
        seq.reserveCapacity(Int(len))
        for _ in 0 ..< len {
            seq.append(try FfiConverterTypeCountryCode.read(from: &buf))
        }
        return seq
    }
}


/**
 * Typealias from the type name used in the UDL file to the builtin type.  This
 * is needed because the UDL type name is used in function/method signatures.
 */
public typealias ConfirmationContext = Data

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeConfirmationContext: FfiConverter {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> ConfirmationContext {
        return try FfiConverterData.read(from: &buf)
    }

    public static func write(_ value: ConfirmationContext, into buf: inout [UInt8]) {
        return FfiConverterData.write(value, into: &buf)
    }

    public static func lift(_ value: RustBuffer) throws -> ConfirmationContext {
        return try FfiConverterData.lift(value)
    }

    public static func lower(_ value: ConfirmationContext) -> RustBuffer {
        return FfiConverterData.lower(value)
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeConfirmationContext_lift(_ value: RustBuffer) throws -> ConfirmationContext {
    return try FfiConverterTypeConfirmationContext.lift(value)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeConfirmationContext_lower(_ value: ConfirmationContext) -> RustBuffer {
    return FfiConverterTypeConfirmationContext.lower(value)
}



/**
 * Typealias from the type name used in the UDL file to the builtin type.  This
 * is needed because the UDL type name is used in function/method signatures.
 */
public typealias InputContext = Data

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeInputContext: FfiConverter {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> InputContext {
        return try FfiConverterData.read(from: &buf)
    }

    public static func write(_ value: InputContext, into buf: inout [UInt8]) {
        return FfiConverterData.write(value, into: &buf)
    }

    public static func lift(_ value: RustBuffer) throws -> InputContext {
        return try FfiConverterData.lift(value)
    }

    public static func lower(_ value: InputContext) -> RustBuffer {
        return FfiConverterData.lower(value)
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeInputContext_lift(_ value: RustBuffer) throws -> InputContext {
    return try FfiConverterTypeInputContext.lift(value)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeInputContext_lower(_ value: InputContext) -> RustBuffer {
    return FfiConverterTypeInputContext.lower(value)
}



/**
 * Typealias from the type name used in the UDL file to the builtin type.  This
 * is needed because the UDL type name is used in function/method signatures.
 */
public typealias Ticket = String

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeTicket: FfiConverter {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> Ticket {
        return try FfiConverterString.read(from: &buf)
    }

    public static func write(_ value: Ticket, into buf: inout [UInt8]) {
        return FfiConverterString.write(value, into: &buf)
    }

    public static func lift(_ value: RustBuffer) throws -> Ticket {
        return try FfiConverterString.lift(value)
    }

    public static func lower(_ value: Ticket) -> RustBuffer {
        return FfiConverterString.lower(value)
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeTicket_lift(_ value: RustBuffer) throws -> Ticket {
    return try FfiConverterTypeTicket.lift(value)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeTicket_lower(_ value: Ticket) -> RustBuffer {
    return FfiConverterTypeTicket.lower(value)
}





/**
 * Typealias from the type name used in the UDL file to the custom type.  This
 * is needed because the UDL type name is used in function/method signatures.
 */
public typealias Url = URL


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeUrl: FfiConverter {

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> Url {
        let builtinValue = try FfiConverterString.read(from: &buf)
        return URL(string: builtinValue)!
    }

    public static func write(_ value: Url, into buf: inout [UInt8]) {
        let builtinValue = String(describing: value)
        return FfiConverterString.write(builtinValue, into: &buf)
    }

    public static func lift(_ value: RustBuffer) throws -> Url {
        let builtinValue = try FfiConverterString.lift(value)
        return URL(string: builtinValue)!
    }

    public static func lower(_ value: Url) -> RustBuffer {
        let builtinValue = String(describing: value)
        return FfiConverterString.lower(builtinValue)
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeUrl_lift(_ value: RustBuffer) throws -> Url {
    return try FfiConverterTypeUrl.lift(value)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeUrl_lower(_ value: Url) -> RustBuffer {
    return FfiConverterTypeUrl.lower(value)
}

private let UNIFFI_RUST_FUTURE_POLL_READY: Int8 = 0
private let UNIFFI_RUST_FUTURE_POLL_MAYBE_READY: Int8 = 1

fileprivate let uniffiContinuationHandleMap = UniffiHandleMap<UnsafeContinuation<Int8, Never>>()

fileprivate func uniffiRustCallAsync<F, T>(
    rustFutureFunc: () -> UInt64,
    pollFunc: (UInt64, @escaping UniffiRustFutureContinuationCallback, UInt64) -> (),
    completeFunc: (UInt64, UnsafeMutablePointer<RustCallStatus>) -> F,
    freeFunc: (UInt64) -> (),
    liftFunc: (F) throws -> T,
    errorHandler: ((RustBuffer) throws -> Swift.Error)?
) async throws -> T {
    // Make sure to call the ensure init function since future creation doesn't have a
    // RustCallStatus param, so doesn't use makeRustCall()
    uniffiEnsureRoutexClientUniffiInitialized()
    let rustFuture = rustFutureFunc()
    defer {
        freeFunc(rustFuture)
    }
    var pollResult: Int8;
    repeat {
        pollResult = await withUnsafeContinuation {
            pollFunc(
                rustFuture,
                uniffiFutureContinuationCallback,
                uniffiContinuationHandleMap.insert(obj: $0)
            )
        }
    } while pollResult != UNIFFI_RUST_FUTURE_POLL_READY

    return try liftFunc(makeRustCall(
        { completeFunc(rustFuture, $0) },
        errorHandler: errorHandler
    ))
}

// Callback handlers for an async calls.  These are invoked by Rust when the future is ready.  They
// lift the return value or error and resume the suspended function.
fileprivate func uniffiFutureContinuationCallback(handle: UInt64, pollResult: Int8) {
    if let continuation = try? uniffiContinuationHandleMap.remove(handle: handle) {
        continuation.resume(returning: pollResult)
    } else {
        print("uniffiFutureContinuationCallback invalid handle")
    }
}

private enum InitializationResult {
    case ok
    case contractVersionMismatch
    case apiChecksumMismatch
}
// Use a global variable to perform the versioning checks. Swift ensures that
// the code inside is only computed once.
private let initializationResult: InitializationResult = {
    // Get the bindings contract version from our ComponentInterface
    let bindings_contract_version = 29
    // Get the scaffolding contract version by calling the into the dylib
    let scaffolding_contract_version = ffi_routex_client_uniffi_uniffi_contract_version()
    if bindings_contract_version != scaffolding_contract_version {
        return InitializationResult.contractVersionMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_authenticatedaccountsresult_jwt() != 25956) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_authenticatedaccountsresult_to_data() != 53535) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_authenticatedcollectpaymentresult_jwt() != 40578) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_authenticatedcollectpaymentresult_to_data() != 60347) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_authenticatedtransactionsresult_jwt() != 62857) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_authenticatedtransactionsresult_to_data() != 41295) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_accounts() != 5041) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_collect_payment() != 11220) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_confirm_accounts() != 56417) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_confirm_collect_payment() != 17005) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_confirm_transactions() != 22741) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_info() != 28406) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_register_redirect_uri() != 24492) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_respond_accounts() != 48232) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_respond_collect_payment() != 55953) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_respond_transactions() != 2780) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_search() != 28299) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_set_redirect_uri() != 47593) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_settle_key() != 58170) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_trace() != 62359) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_trace_id() != 58761) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_transactions() != 47915) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_constructor_routexclient_new() != 55859) {
        return InitializationResult.apiChecksumMismatch
    }

    uniffiEnsureKitxCoreInitialized()
    uniffiEnsureRoutexApiInitialized()
    return InitializationResult.ok
}()

// Make the ensure init function public so that other modules which have external type references to
// our types can call it.
public func uniffiEnsureRoutexClientUniffiInitialized() {
    switch initializationResult {
    case .ok:
        break
    case .contractVersionMismatch:
        fatalError("UniFFI contract version mismatch: try cleaning and rebuilding your project")
    case .apiChecksumMismatch:
        fatalError("UniFFI API checksum mismatch: try cleaning and rebuilding your project")
    }
}

// swiftlint:enable all