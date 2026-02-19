// swiftlint:disable all
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
// Initial value and increment amount for handles. 
// These ensure that SWIFT handles always have the lowest bit set
fileprivate let UNIFFI_HANDLEMAP_INITIAL: UInt64 = 1
fileprivate let UNIFFI_HANDLEMAP_DELTA: UInt64 = 2

fileprivate final class UniffiHandleMap<T>: @unchecked Sendable {
    // All mutation happens with this lock held, which is why we implement @unchecked Sendable.
    private let lock = NSLock()
    private var map: [UInt64: T] = [:]
    private var currentHandle: UInt64 = UNIFFI_HANDLEMAP_INITIAL

    func insert(obj: T) -> UInt64 {
        lock.withLock {
            return doInsert(obj)
        }
    }

    // Low-level insert function, this assumes `lock` is held.
    private func doInsert(_ obj: T) -> UInt64 {
        let handle = currentHandle
        currentHandle += UNIFFI_HANDLEMAP_DELTA
        map[handle] = obj
        return handle
    }

     func get(handle: UInt64) throws -> T {
        try lock.withLock {
            guard let obj = map[handle] else {
                throw UniffiInternalError.unexpectedStaleHandle
            }
            return obj
        }
    }

     func clone(handle: UInt64) throws -> UInt64 {
        try lock.withLock {
            guard let obj = map[handle] else {
                throw UniffiInternalError.unexpectedStaleHandle
            }
            return doInsert(obj)
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




public protocol AuthenticatedAccountsResultProtocol: AnyObject, Sendable {
    
    func jwt()  -> String
    
    func toData()  -> AccountsResult
    
}
open class AuthenticatedAccountsResult: AuthenticatedAccountsResultProtocol, @unchecked Sendable {
    fileprivate let handle: UInt64

    /// Used to instantiate a [FFIObject] without an actual handle, for fakes in tests, mostly.
#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public struct NoHandle {
        public init() {}
    }

    // TODO: We'd like this to be `private` but for Swifty reasons,
    // we can't implement `FfiConverter` without making this `required` and we can't
    // make it `required` without making it `public`.
#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    required public init(unsafeFromHandle handle: UInt64) {
        self.handle = handle
    }

    // This constructor can be used to instantiate a fake object.
    // - Parameter noHandle: Placeholder value so we can have a constructor separate from the default empty one that may be implemented for classes extending [FFIObject].
    //
    // - Warning:
    //     Any object instantiated with this constructor cannot be passed to an actual Rust-backed object. Since there isn't a backing handle the FFI lower functions will crash.
#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public init(noHandle: NoHandle) {
        self.handle = 0
    }

#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public func uniffiCloneHandle() -> UInt64 {
        return try! rustCall { uniffi_routex_client_uniffi_fn_clone_authenticatedaccountsresult(self.handle, $0) }
    }
    // No primary constructor declared for this class.

    deinit {
        try! rustCall { uniffi_routex_client_uniffi_fn_free_authenticatedaccountsresult(handle, $0) }
    }

    

    
open func jwt() -> String  {
    return try!  FfiConverterString.lift(try! rustCall() {
    uniffi_routex_client_uniffi_fn_method_authenticatedaccountsresult_jwt(
            self.uniffiCloneHandle(),$0
    )
})
}
    
open func toData() -> AccountsResult  {
    return try!  FfiConverterTypeAccountsResult_lift(try! rustCall() {
    uniffi_routex_client_uniffi_fn_method_authenticatedaccountsresult_to_data(
            self.uniffiCloneHandle(),$0
    )
})
}
    

    
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeAuthenticatedAccountsResult: FfiConverter {
    typealias FfiType = UInt64
    typealias SwiftType = AuthenticatedAccountsResult

    public static func lift(_ handle: UInt64) throws -> AuthenticatedAccountsResult {
        return AuthenticatedAccountsResult(unsafeFromHandle: handle)
    }

    public static func lower(_ value: AuthenticatedAccountsResult) -> UInt64 {
        return value.uniffiCloneHandle()
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> AuthenticatedAccountsResult {
        let handle: UInt64 = try readInt(&buf)
        return try lift(handle)
    }

    public static func write(_ value: AuthenticatedAccountsResult, into buf: inout [UInt8]) {
        writeInt(&buf, lower(value))
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAuthenticatedAccountsResult_lift(_ handle: UInt64) throws -> AuthenticatedAccountsResult {
    return try FfiConverterTypeAuthenticatedAccountsResult.lift(handle)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAuthenticatedAccountsResult_lower(_ value: AuthenticatedAccountsResult) -> UInt64 {
    return FfiConverterTypeAuthenticatedAccountsResult.lower(value)
}






public protocol AuthenticatedBalancesResultProtocol: AnyObject, Sendable {
    
    func jwt()  -> String
    
    func toData()  -> BalancesResult
    
}
open class AuthenticatedBalancesResult: AuthenticatedBalancesResultProtocol, @unchecked Sendable {
    fileprivate let handle: UInt64

    /// Used to instantiate a [FFIObject] without an actual handle, for fakes in tests, mostly.
#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public struct NoHandle {
        public init() {}
    }

    // TODO: We'd like this to be `private` but for Swifty reasons,
    // we can't implement `FfiConverter` without making this `required` and we can't
    // make it `required` without making it `public`.
#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    required public init(unsafeFromHandle handle: UInt64) {
        self.handle = handle
    }

    // This constructor can be used to instantiate a fake object.
    // - Parameter noHandle: Placeholder value so we can have a constructor separate from the default empty one that may be implemented for classes extending [FFIObject].
    //
    // - Warning:
    //     Any object instantiated with this constructor cannot be passed to an actual Rust-backed object. Since there isn't a backing handle the FFI lower functions will crash.
#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public init(noHandle: NoHandle) {
        self.handle = 0
    }

#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public func uniffiCloneHandle() -> UInt64 {
        return try! rustCall { uniffi_routex_client_uniffi_fn_clone_authenticatedbalancesresult(self.handle, $0) }
    }
    // No primary constructor declared for this class.

    deinit {
        try! rustCall { uniffi_routex_client_uniffi_fn_free_authenticatedbalancesresult(handle, $0) }
    }

    

    
open func jwt() -> String  {
    return try!  FfiConverterString.lift(try! rustCall() {
    uniffi_routex_client_uniffi_fn_method_authenticatedbalancesresult_jwt(
            self.uniffiCloneHandle(),$0
    )
})
}
    
open func toData() -> BalancesResult  {
    return try!  FfiConverterTypeBalancesResult_lift(try! rustCall() {
    uniffi_routex_client_uniffi_fn_method_authenticatedbalancesresult_to_data(
            self.uniffiCloneHandle(),$0
    )
})
}
    

    
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeAuthenticatedBalancesResult: FfiConverter {
    typealias FfiType = UInt64
    typealias SwiftType = AuthenticatedBalancesResult

    public static func lift(_ handle: UInt64) throws -> AuthenticatedBalancesResult {
        return AuthenticatedBalancesResult(unsafeFromHandle: handle)
    }

    public static func lower(_ value: AuthenticatedBalancesResult) -> UInt64 {
        return value.uniffiCloneHandle()
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> AuthenticatedBalancesResult {
        let handle: UInt64 = try readInt(&buf)
        return try lift(handle)
    }

    public static func write(_ value: AuthenticatedBalancesResult, into buf: inout [UInt8]) {
        writeInt(&buf, lower(value))
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAuthenticatedBalancesResult_lift(_ handle: UInt64) throws -> AuthenticatedBalancesResult {
    return try FfiConverterTypeAuthenticatedBalancesResult.lift(handle)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAuthenticatedBalancesResult_lower(_ value: AuthenticatedBalancesResult) -> UInt64 {
    return FfiConverterTypeAuthenticatedBalancesResult.lower(value)
}






public protocol AuthenticatedCollectPaymentResultProtocol: AnyObject, Sendable {
    
    func jwt()  -> String
    
    func toData()  -> CollectPaymentResult
    
}
open class AuthenticatedCollectPaymentResult: AuthenticatedCollectPaymentResultProtocol, @unchecked Sendable {
    fileprivate let handle: UInt64

    /// Used to instantiate a [FFIObject] without an actual handle, for fakes in tests, mostly.
#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public struct NoHandle {
        public init() {}
    }

    // TODO: We'd like this to be `private` but for Swifty reasons,
    // we can't implement `FfiConverter` without making this `required` and we can't
    // make it `required` without making it `public`.
#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    required public init(unsafeFromHandle handle: UInt64) {
        self.handle = handle
    }

    // This constructor can be used to instantiate a fake object.
    // - Parameter noHandle: Placeholder value so we can have a constructor separate from the default empty one that may be implemented for classes extending [FFIObject].
    //
    // - Warning:
    //     Any object instantiated with this constructor cannot be passed to an actual Rust-backed object. Since there isn't a backing handle the FFI lower functions will crash.
#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public init(noHandle: NoHandle) {
        self.handle = 0
    }

#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public func uniffiCloneHandle() -> UInt64 {
        return try! rustCall { uniffi_routex_client_uniffi_fn_clone_authenticatedcollectpaymentresult(self.handle, $0) }
    }
    // No primary constructor declared for this class.

    deinit {
        try! rustCall { uniffi_routex_client_uniffi_fn_free_authenticatedcollectpaymentresult(handle, $0) }
    }

    

    
open func jwt() -> String  {
    return try!  FfiConverterString.lift(try! rustCall() {
    uniffi_routex_client_uniffi_fn_method_authenticatedcollectpaymentresult_jwt(
            self.uniffiCloneHandle(),$0
    )
})
}
    
open func toData() -> CollectPaymentResult  {
    return try!  FfiConverterTypeCollectPaymentResult_lift(try! rustCall() {
    uniffi_routex_client_uniffi_fn_method_authenticatedcollectpaymentresult_to_data(
            self.uniffiCloneHandle(),$0
    )
})
}
    

    
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeAuthenticatedCollectPaymentResult: FfiConverter {
    typealias FfiType = UInt64
    typealias SwiftType = AuthenticatedCollectPaymentResult

    public static func lift(_ handle: UInt64) throws -> AuthenticatedCollectPaymentResult {
        return AuthenticatedCollectPaymentResult(unsafeFromHandle: handle)
    }

    public static func lower(_ value: AuthenticatedCollectPaymentResult) -> UInt64 {
        return value.uniffiCloneHandle()
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> AuthenticatedCollectPaymentResult {
        let handle: UInt64 = try readInt(&buf)
        return try lift(handle)
    }

    public static func write(_ value: AuthenticatedCollectPaymentResult, into buf: inout [UInt8]) {
        writeInt(&buf, lower(value))
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAuthenticatedCollectPaymentResult_lift(_ handle: UInt64) throws -> AuthenticatedCollectPaymentResult {
    return try FfiConverterTypeAuthenticatedCollectPaymentResult.lift(handle)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAuthenticatedCollectPaymentResult_lower(_ value: AuthenticatedCollectPaymentResult) -> UInt64 {
    return FfiConverterTypeAuthenticatedCollectPaymentResult.lower(value)
}






public protocol AuthenticatedTransactionsResultProtocol: AnyObject, Sendable {
    
    func jwt()  -> String
    
    func toData()  -> TransactionsResult
    
}
open class AuthenticatedTransactionsResult: AuthenticatedTransactionsResultProtocol, @unchecked Sendable {
    fileprivate let handle: UInt64

    /// Used to instantiate a [FFIObject] without an actual handle, for fakes in tests, mostly.
#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public struct NoHandle {
        public init() {}
    }

    // TODO: We'd like this to be `private` but for Swifty reasons,
    // we can't implement `FfiConverter` without making this `required` and we can't
    // make it `required` without making it `public`.
#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    required public init(unsafeFromHandle handle: UInt64) {
        self.handle = handle
    }

    // This constructor can be used to instantiate a fake object.
    // - Parameter noHandle: Placeholder value so we can have a constructor separate from the default empty one that may be implemented for classes extending [FFIObject].
    //
    // - Warning:
    //     Any object instantiated with this constructor cannot be passed to an actual Rust-backed object. Since there isn't a backing handle the FFI lower functions will crash.
#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public init(noHandle: NoHandle) {
        self.handle = 0
    }

#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public func uniffiCloneHandle() -> UInt64 {
        return try! rustCall { uniffi_routex_client_uniffi_fn_clone_authenticatedtransactionsresult(self.handle, $0) }
    }
    // No primary constructor declared for this class.

    deinit {
        try! rustCall { uniffi_routex_client_uniffi_fn_free_authenticatedtransactionsresult(handle, $0) }
    }

    

    
open func jwt() -> String  {
    return try!  FfiConverterString.lift(try! rustCall() {
    uniffi_routex_client_uniffi_fn_method_authenticatedtransactionsresult_jwt(
            self.uniffiCloneHandle(),$0
    )
})
}
    
open func toData() -> TransactionsResult  {
    return try!  FfiConverterTypeTransactionsResult_lift(try! rustCall() {
    uniffi_routex_client_uniffi_fn_method_authenticatedtransactionsresult_to_data(
            self.uniffiCloneHandle(),$0
    )
})
}
    

    
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeAuthenticatedTransactionsResult: FfiConverter {
    typealias FfiType = UInt64
    typealias SwiftType = AuthenticatedTransactionsResult

    public static func lift(_ handle: UInt64) throws -> AuthenticatedTransactionsResult {
        return AuthenticatedTransactionsResult(unsafeFromHandle: handle)
    }

    public static func lower(_ value: AuthenticatedTransactionsResult) -> UInt64 {
        return value.uniffiCloneHandle()
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> AuthenticatedTransactionsResult {
        let handle: UInt64 = try readInt(&buf)
        return try lift(handle)
    }

    public static func write(_ value: AuthenticatedTransactionsResult, into buf: inout [UInt8]) {
        writeInt(&buf, lower(value))
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAuthenticatedTransactionsResult_lift(_ handle: UInt64) throws -> AuthenticatedTransactionsResult {
    return try FfiConverterTypeAuthenticatedTransactionsResult.lift(handle)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAuthenticatedTransactionsResult_lower(_ value: AuthenticatedTransactionsResult) -> UInt64 {
    return FfiConverterTypeAuthenticatedTransactionsResult.lower(value)
}






public protocol AuthenticatedTransferResultProtocol: AnyObject, Sendable {
    
    func jwt()  -> String
    
    func toData()  -> TransferResult
    
}
open class AuthenticatedTransferResult: AuthenticatedTransferResultProtocol, @unchecked Sendable {
    fileprivate let handle: UInt64

    /// Used to instantiate a [FFIObject] without an actual handle, for fakes in tests, mostly.
#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public struct NoHandle {
        public init() {}
    }

    // TODO: We'd like this to be `private` but for Swifty reasons,
    // we can't implement `FfiConverter` without making this `required` and we can't
    // make it `required` without making it `public`.
#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    required public init(unsafeFromHandle handle: UInt64) {
        self.handle = handle
    }

    // This constructor can be used to instantiate a fake object.
    // - Parameter noHandle: Placeholder value so we can have a constructor separate from the default empty one that may be implemented for classes extending [FFIObject].
    //
    // - Warning:
    //     Any object instantiated with this constructor cannot be passed to an actual Rust-backed object. Since there isn't a backing handle the FFI lower functions will crash.
#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public init(noHandle: NoHandle) {
        self.handle = 0
    }

#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public func uniffiCloneHandle() -> UInt64 {
        return try! rustCall { uniffi_routex_client_uniffi_fn_clone_authenticatedtransferresult(self.handle, $0) }
    }
    // No primary constructor declared for this class.

    deinit {
        try! rustCall { uniffi_routex_client_uniffi_fn_free_authenticatedtransferresult(handle, $0) }
    }

    

    
open func jwt() -> String  {
    return try!  FfiConverterString.lift(try! rustCall() {
    uniffi_routex_client_uniffi_fn_method_authenticatedtransferresult_jwt(
            self.uniffiCloneHandle(),$0
    )
})
}
    
open func toData() -> TransferResult  {
    return try!  FfiConverterTypeTransferResult_lift(try! rustCall() {
    uniffi_routex_client_uniffi_fn_method_authenticatedtransferresult_to_data(
            self.uniffiCloneHandle(),$0
    )
})
}
    

    
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeAuthenticatedTransferResult: FfiConverter {
    typealias FfiType = UInt64
    typealias SwiftType = AuthenticatedTransferResult

    public static func lift(_ handle: UInt64) throws -> AuthenticatedTransferResult {
        return AuthenticatedTransferResult(unsafeFromHandle: handle)
    }

    public static func lower(_ value: AuthenticatedTransferResult) -> UInt64 {
        return value.uniffiCloneHandle()
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> AuthenticatedTransferResult {
        let handle: UInt64 = try readInt(&buf)
        return try lift(handle)
    }

    public static func write(_ value: AuthenticatedTransferResult, into buf: inout [UInt8]) {
        writeInt(&buf, lower(value))
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAuthenticatedTransferResult_lift(_ handle: UInt64) throws -> AuthenticatedTransferResult {
    return try FfiConverterTypeAuthenticatedTransferResult.lift(handle)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAuthenticatedTransferResult_lower(_ value: AuthenticatedTransferResult) -> UInt64 {
    return FfiConverterTypeAuthenticatedTransferResult.lower(value)
}






public protocol RoutexClientProtocol: AnyObject, Sendable {
    
    func accounts(credentials: Credentials, session: Session?, recurringConsents: Bool?, ticket: Ticket, fields: [AccountField], filter: AccountFilter?) async throws  -> AccountsResponse
    
    func balances(credentials: Credentials, session: Session?, recurringConsents: Bool?, ticket: Ticket, accounts: [AccountReference]) async throws  -> BalancesResponse
    
    func collectPayment(credentials: Credentials, session: Session?, recurringConsents: Bool?, ticket: Ticket, account: AccountReference?) async throws  -> CollectPaymentResponse
    
    func confirmAccounts(ticket: Ticket, context: ConfirmationContext) async throws  -> AccountsResponse
    
    func confirmBalances(ticket: Ticket, context: ConfirmationContext) async throws  -> BalancesResponse
    
    func confirmCollectPayment(ticket: Ticket, context: ConfirmationContext) async throws  -> CollectPaymentResponse
    
    func confirmTransactions(ticket: Ticket, context: ConfirmationContext) async throws  -> TransactionsResponse
    
    func confirmTransfer(ticket: Ticket, context: ConfirmationContext) async throws  -> TransferResponse
    
    func info(ticket: Ticket, connectionId: ConnectionId) async throws  -> ConnectionInfo
    
    func registerRedirectUri(ticket: Ticket, handle: String, redirectUri: String) async throws  -> Url
    
    func respondAccounts(ticket: Ticket, context: InputContext, response: String) async throws  -> AccountsResponse
    
    func respondBalances(ticket: Ticket, context: InputContext, response: String) async throws  -> BalancesResponse
    
    func respondCollectPayment(ticket: Ticket, context: InputContext, response: String) async throws  -> CollectPaymentResponse
    
    func respondTransactions(ticket: Ticket, context: InputContext, response: String) async throws  -> TransactionsResponse
    
    func respondTransfer(ticket: Ticket, context: InputContext, response: String) async throws  -> TransferResponse
    
    func search(ticket: Ticket, filters: [SearchFilter], ibanDetection: Bool, limit: UInt32?) async throws  -> [ConnectionInfo]
    
    func setRedirectUri(redirectUri: String) throws 
    
    func settleKey(ticket: Ticket) async throws 
    
    func systemVersion(ticketId: String) async  -> String?
    
    func trace(ticket: Ticket, traceId: Data) async throws  -> String
    
    func traceId()  -> Data?
    
    func transactions(credentials: Credentials, session: Session?, recurringConsents: Bool?, ticket: Ticket) async throws  -> TransactionsResponse
    
    func transfer(credentials: Credentials, session: Session?, recurringConsents: Bool?, ticket: Ticket, product: PaymentProduct, details: [TransferDetails], debtorAccount: AccountReference?, debtorName: String?, requestedExecutionDate: DateTime?) async throws  -> TransferResponse
    
}
open class RoutexClient: RoutexClientProtocol, @unchecked Sendable {
    fileprivate let handle: UInt64

    /// Used to instantiate a [FFIObject] without an actual handle, for fakes in tests, mostly.
#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public struct NoHandle {
        public init() {}
    }

    // TODO: We'd like this to be `private` but for Swifty reasons,
    // we can't implement `FfiConverter` without making this `required` and we can't
    // make it `required` without making it `public`.
#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    required public init(unsafeFromHandle handle: UInt64) {
        self.handle = handle
    }

    // This constructor can be used to instantiate a fake object.
    // - Parameter noHandle: Placeholder value so we can have a constructor separate from the default empty one that may be implemented for classes extending [FFIObject].
    //
    // - Warning:
    //     Any object instantiated with this constructor cannot be passed to an actual Rust-backed object. Since there isn't a backing handle the FFI lower functions will crash.
#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public init(noHandle: NoHandle) {
        self.handle = 0
    }

#if swift(>=5.8)
    @_documentation(visibility: private)
#endif
    public func uniffiCloneHandle() -> UInt64 {
        return try! rustCall { uniffi_routex_client_uniffi_fn_clone_routexclient(self.handle, $0) }
    }
public convenience init(distribution: String, version: String, url: Url) {
    let handle =
        try! rustCall() {
    uniffi_routex_client_uniffi_fn_constructor_routexclient_new(
        FfiConverterString.lower(distribution),
        FfiConverterString.lower(version),
        FfiConverterTypeUrl_lower(url),$0
    )
}
    self.init(unsafeFromHandle: handle)
}

    deinit {
        try! rustCall { uniffi_routex_client_uniffi_fn_free_routexclient(handle, $0) }
    }

    

    
open func accounts(credentials: Credentials, session: Session?, recurringConsents: Bool?, ticket: Ticket, fields: [AccountField], filter: AccountFilter? = nil)async throws  -> AccountsResponse  {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_accounts(
                    self.uniffiCloneHandle(),
                    FfiConverterTypeCredentials_lower(credentials),FfiConverterOptionTypeSession.lower(session),FfiConverterOptionBool.lower(recurringConsents),FfiConverterTypeTicket_lower(ticket),FfiConverterSequenceTypeAccountField.lower(fields),FfiConverterOptionTypeAccountFilter.lower(filter)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_rust_buffer,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_rust_buffer,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_rust_buffer,
            liftFunc: FfiConverterTypeAccountsResponse_lift,
            errorHandler: FfiConverterTypeRoutexClientError_lift
        )
}
    
open func balances(credentials: Credentials, session: Session?, recurringConsents: Bool?, ticket: Ticket, accounts: [AccountReference])async throws  -> BalancesResponse  {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_balances(
                    self.uniffiCloneHandle(),
                    FfiConverterTypeCredentials_lower(credentials),FfiConverterOptionTypeSession.lower(session),FfiConverterOptionBool.lower(recurringConsents),FfiConverterTypeTicket_lower(ticket),FfiConverterSequenceTypeAccountReference.lower(accounts)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_rust_buffer,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_rust_buffer,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_rust_buffer,
            liftFunc: FfiConverterTypeBalancesResponse_lift,
            errorHandler: FfiConverterTypeRoutexClientError_lift
        )
}
    
open func collectPayment(credentials: Credentials, session: Session?, recurringConsents: Bool?, ticket: Ticket, account: AccountReference? = nil)async throws  -> CollectPaymentResponse  {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_collect_payment(
                    self.uniffiCloneHandle(),
                    FfiConverterTypeCredentials_lower(credentials),FfiConverterOptionTypeSession.lower(session),FfiConverterOptionBool.lower(recurringConsents),FfiConverterTypeTicket_lower(ticket),FfiConverterOptionTypeAccountReference.lower(account)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_rust_buffer,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_rust_buffer,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_rust_buffer,
            liftFunc: FfiConverterTypeCollectPaymentResponse_lift,
            errorHandler: FfiConverterTypeRoutexClientError_lift
        )
}
    
open func confirmAccounts(ticket: Ticket, context: ConfirmationContext)async throws  -> AccountsResponse  {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_confirm_accounts(
                    self.uniffiCloneHandle(),
                    FfiConverterTypeTicket_lower(ticket),FfiConverterTypeConfirmationContext_lower(context)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_rust_buffer,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_rust_buffer,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_rust_buffer,
            liftFunc: FfiConverterTypeAccountsResponse_lift,
            errorHandler: FfiConverterTypeRoutexClientError_lift
        )
}
    
open func confirmBalances(ticket: Ticket, context: ConfirmationContext)async throws  -> BalancesResponse  {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_confirm_balances(
                    self.uniffiCloneHandle(),
                    FfiConverterTypeTicket_lower(ticket),FfiConverterTypeConfirmationContext_lower(context)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_rust_buffer,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_rust_buffer,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_rust_buffer,
            liftFunc: FfiConverterTypeBalancesResponse_lift,
            errorHandler: FfiConverterTypeRoutexClientError_lift
        )
}
    
open func confirmCollectPayment(ticket: Ticket, context: ConfirmationContext)async throws  -> CollectPaymentResponse  {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_confirm_collect_payment(
                    self.uniffiCloneHandle(),
                    FfiConverterTypeTicket_lower(ticket),FfiConverterTypeConfirmationContext_lower(context)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_rust_buffer,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_rust_buffer,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_rust_buffer,
            liftFunc: FfiConverterTypeCollectPaymentResponse_lift,
            errorHandler: FfiConverterTypeRoutexClientError_lift
        )
}
    
open func confirmTransactions(ticket: Ticket, context: ConfirmationContext)async throws  -> TransactionsResponse  {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_confirm_transactions(
                    self.uniffiCloneHandle(),
                    FfiConverterTypeTicket_lower(ticket),FfiConverterTypeConfirmationContext_lower(context)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_rust_buffer,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_rust_buffer,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_rust_buffer,
            liftFunc: FfiConverterTypeTransactionsResponse_lift,
            errorHandler: FfiConverterTypeRoutexClientError_lift
        )
}
    
open func confirmTransfer(ticket: Ticket, context: ConfirmationContext)async throws  -> TransferResponse  {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_confirm_transfer(
                    self.uniffiCloneHandle(),
                    FfiConverterTypeTicket_lower(ticket),FfiConverterTypeConfirmationContext_lower(context)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_rust_buffer,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_rust_buffer,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_rust_buffer,
            liftFunc: FfiConverterTypeTransferResponse_lift,
            errorHandler: FfiConverterTypeRoutexClientError_lift
        )
}
    
open func info(ticket: Ticket, connectionId: ConnectionId)async throws  -> ConnectionInfo  {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_info(
                    self.uniffiCloneHandle(),
                    FfiConverterTypeTicket_lower(ticket),FfiConverterTypeConnectionId_lower(connectionId)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_rust_buffer,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_rust_buffer,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_rust_buffer,
            liftFunc: FfiConverterTypeConnectionInfo_lift,
            errorHandler: FfiConverterTypeRoutexClientError_lift
        )
}
    
open func registerRedirectUri(ticket: Ticket, handle: String, redirectUri: String)async throws  -> Url  {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_register_redirect_uri(
                    self.uniffiCloneHandle(),
                    FfiConverterTypeTicket_lower(ticket),FfiConverterString.lower(handle),FfiConverterString.lower(redirectUri)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_rust_buffer,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_rust_buffer,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_rust_buffer,
            liftFunc: FfiConverterTypeUrl_lift,
            errorHandler: FfiConverterTypeRoutexClientError_lift
        )
}
    
open func respondAccounts(ticket: Ticket, context: InputContext, response: String)async throws  -> AccountsResponse  {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_respond_accounts(
                    self.uniffiCloneHandle(),
                    FfiConverterTypeTicket_lower(ticket),FfiConverterTypeInputContext_lower(context),FfiConverterString.lower(response)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_rust_buffer,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_rust_buffer,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_rust_buffer,
            liftFunc: FfiConverterTypeAccountsResponse_lift,
            errorHandler: FfiConverterTypeRoutexClientError_lift
        )
}
    
open func respondBalances(ticket: Ticket, context: InputContext, response: String)async throws  -> BalancesResponse  {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_respond_balances(
                    self.uniffiCloneHandle(),
                    FfiConverterTypeTicket_lower(ticket),FfiConverterTypeInputContext_lower(context),FfiConverterString.lower(response)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_rust_buffer,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_rust_buffer,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_rust_buffer,
            liftFunc: FfiConverterTypeBalancesResponse_lift,
            errorHandler: FfiConverterTypeRoutexClientError_lift
        )
}
    
open func respondCollectPayment(ticket: Ticket, context: InputContext, response: String)async throws  -> CollectPaymentResponse  {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_respond_collect_payment(
                    self.uniffiCloneHandle(),
                    FfiConverterTypeTicket_lower(ticket),FfiConverterTypeInputContext_lower(context),FfiConverterString.lower(response)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_rust_buffer,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_rust_buffer,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_rust_buffer,
            liftFunc: FfiConverterTypeCollectPaymentResponse_lift,
            errorHandler: FfiConverterTypeRoutexClientError_lift
        )
}
    
open func respondTransactions(ticket: Ticket, context: InputContext, response: String)async throws  -> TransactionsResponse  {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_respond_transactions(
                    self.uniffiCloneHandle(),
                    FfiConverterTypeTicket_lower(ticket),FfiConverterTypeInputContext_lower(context),FfiConverterString.lower(response)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_rust_buffer,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_rust_buffer,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_rust_buffer,
            liftFunc: FfiConverterTypeTransactionsResponse_lift,
            errorHandler: FfiConverterTypeRoutexClientError_lift
        )
}
    
open func respondTransfer(ticket: Ticket, context: InputContext, response: String)async throws  -> TransferResponse  {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_respond_transfer(
                    self.uniffiCloneHandle(),
                    FfiConverterTypeTicket_lower(ticket),FfiConverterTypeInputContext_lower(context),FfiConverterString.lower(response)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_rust_buffer,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_rust_buffer,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_rust_buffer,
            liftFunc: FfiConverterTypeTransferResponse_lift,
            errorHandler: FfiConverterTypeRoutexClientError_lift
        )
}
    
open func search(ticket: Ticket, filters: [SearchFilter], ibanDetection: Bool, limit: UInt32? = nil)async throws  -> [ConnectionInfo]  {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_search(
                    self.uniffiCloneHandle(),
                    FfiConverterTypeTicket_lower(ticket),FfiConverterSequenceTypeSearchFilter.lower(filters),FfiConverterBool.lower(ibanDetection),FfiConverterOptionUInt32.lower(limit)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_rust_buffer,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_rust_buffer,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_rust_buffer,
            liftFunc: FfiConverterSequenceTypeConnectionInfo.lift,
            errorHandler: FfiConverterTypeRoutexClientError_lift
        )
}
    
open func setRedirectUri(redirectUri: String)throws   {try rustCallWithError(FfiConverterTypeRoutexClientError_lift) {
    uniffi_routex_client_uniffi_fn_method_routexclient_set_redirect_uri(
            self.uniffiCloneHandle(),
        FfiConverterString.lower(redirectUri),$0
    )
}
}
    
open func settleKey(ticket: Ticket)async throws   {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_settle_key(
                    self.uniffiCloneHandle(),
                    FfiConverterTypeTicket_lower(ticket)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_void,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_void,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_void,
            liftFunc: { $0 },
            errorHandler: FfiConverterTypeRoutexClientError_lift
        )
}
    
open func systemVersion(ticketId: String)async  -> String?  {
    return
        try!  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_system_version(
                    self.uniffiCloneHandle(),
                    FfiConverterString.lower(ticketId)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_rust_buffer,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_rust_buffer,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_rust_buffer,
            liftFunc: FfiConverterOptionString.lift,
            errorHandler: nil
            
        )
}
    
open func trace(ticket: Ticket, traceId: Data)async throws  -> String  {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_trace(
                    self.uniffiCloneHandle(),
                    FfiConverterTypeTicket_lower(ticket),FfiConverterData.lower(traceId)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_rust_buffer,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_rust_buffer,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_rust_buffer,
            liftFunc: FfiConverterString.lift,
            errorHandler: FfiConverterTypeRoutexClientError_lift
        )
}
    
open func traceId() -> Data?  {
    return try!  FfiConverterOptionData.lift(try! rustCall() {
    uniffi_routex_client_uniffi_fn_method_routexclient_trace_id(
            self.uniffiCloneHandle(),$0
    )
})
}
    
open func transactions(credentials: Credentials, session: Session?, recurringConsents: Bool?, ticket: Ticket)async throws  -> TransactionsResponse  {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_transactions(
                    self.uniffiCloneHandle(),
                    FfiConverterTypeCredentials_lower(credentials),FfiConverterOptionTypeSession.lower(session),FfiConverterOptionBool.lower(recurringConsents),FfiConverterTypeTicket_lower(ticket)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_rust_buffer,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_rust_buffer,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_rust_buffer,
            liftFunc: FfiConverterTypeTransactionsResponse_lift,
            errorHandler: FfiConverterTypeRoutexClientError_lift
        )
}
    
open func transfer(credentials: Credentials, session: Session?, recurringConsents: Bool?, ticket: Ticket, product: PaymentProduct, details: [TransferDetails], debtorAccount: AccountReference? = nil, debtorName: String? = nil, requestedExecutionDate: DateTime? = nil)async throws  -> TransferResponse  {
    return
        try  await uniffiRustCallAsync(
            rustFutureFunc: {
                uniffi_routex_client_uniffi_fn_method_routexclient_transfer(
                    self.uniffiCloneHandle(),
                    FfiConverterTypeCredentials_lower(credentials),FfiConverterOptionTypeSession.lower(session),FfiConverterOptionBool.lower(recurringConsents),FfiConverterTypeTicket_lower(ticket),FfiConverterTypePaymentProduct_lower(product),FfiConverterSequenceTypeTransferDetails.lower(details),FfiConverterOptionTypeAccountReference.lower(debtorAccount),FfiConverterOptionString.lower(debtorName),FfiConverterOptionTypeDateTime.lower(requestedExecutionDate)
                )
            },
            pollFunc: ffi_routex_client_uniffi_rust_future_poll_rust_buffer,
            completeFunc: ffi_routex_client_uniffi_rust_future_complete_rust_buffer,
            freeFunc: ffi_routex_client_uniffi_rust_future_free_rust_buffer,
            liftFunc: FfiConverterTypeTransferResponse_lift,
            errorHandler: FfiConverterTypeRoutexClientError_lift
        )
}
    

    
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeRoutexClient: FfiConverter {
    typealias FfiType = UInt64
    typealias SwiftType = RoutexClient

    public static func lift(_ handle: UInt64) throws -> RoutexClient {
        return RoutexClient(unsafeFromHandle: handle)
    }

    public static func lower(_ value: RoutexClient) -> UInt64 {
        return value.uniffiCloneHandle()
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> RoutexClient {
        let handle: UInt64 = try readInt(&buf)
        return try lift(handle)
    }

    public static func write(_ value: RoutexClient, into buf: inout [UInt8]) {
        writeInt(&buf, lower(value))
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeRoutexClient_lift(_ handle: UInt64) throws -> RoutexClient {
    return try FfiConverterTypeRoutexClient.lift(handle)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeRoutexClient_lower(_ value: RoutexClient) -> UInt64 {
    return FfiConverterTypeRoutexClient.lower(value)
}




public struct AccountsResult: Equatable, Hashable {
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


public struct BalancesResult: Equatable, Hashable {
    public var data: Balances
    public var ticketId: String
    public var timestamp: Date

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(data: Balances, ticketId: String, timestamp: Date) {
        self.data = data
        self.ticketId = ticketId
        self.timestamp = timestamp
    }

    
}

#if compiler(>=6)
extension BalancesResult: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeBalancesResult: FfiConverterRustBuffer {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> BalancesResult {
        return
            try BalancesResult(
                data: FfiConverterTypeBalances.read(from: &buf), 
                ticketId: FfiConverterString.read(from: &buf), 
                timestamp: FfiConverterTimestamp.read(from: &buf)
        )
    }

    public static func write(_ value: BalancesResult, into buf: inout [UInt8]) {
        FfiConverterTypeBalances.write(value.data, into: &buf)
        FfiConverterString.write(value.ticketId, into: &buf)
        FfiConverterTimestamp.write(value.timestamp, into: &buf)
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeBalancesResult_lift(_ buf: RustBuffer) throws -> BalancesResult {
    return try FfiConverterTypeBalancesResult.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeBalancesResult_lower(_ value: BalancesResult) -> RustBuffer {
    return FfiConverterTypeBalancesResult.lower(value)
}


public struct CollectPaymentResult: Equatable, Hashable {
    public var data: PaymentInitiation
    public var ticketId: String
    public var timestamp: Date

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(data: PaymentInitiation, ticketId: String, timestamp: Date) {
        self.data = data
        self.ticketId = ticketId
        self.timestamp = timestamp
    }

    
}

#if compiler(>=6)
extension CollectPaymentResult: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeCollectPaymentResult: FfiConverterRustBuffer {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> CollectPaymentResult {
        return
            try CollectPaymentResult(
                data: FfiConverterTypePaymentInitiation.read(from: &buf), 
                ticketId: FfiConverterString.read(from: &buf), 
                timestamp: FfiConverterTimestamp.read(from: &buf)
        )
    }

    public static func write(_ value: CollectPaymentResult, into buf: inout [UInt8]) {
        FfiConverterTypePaymentInitiation.write(value.data, into: &buf)
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


public struct TransactionsResult: Equatable, Hashable {
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


public struct TransferResult: Equatable, Hashable {
    public var data: Transfer
    public var ticketId: String
    public var timestamp: Date

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(data: Transfer, ticketId: String, timestamp: Date) {
        self.data = data
        self.ticketId = ticketId
        self.timestamp = timestamp
    }

    
}

#if compiler(>=6)
extension TransferResult: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeTransferResult: FfiConverterRustBuffer {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> TransferResult {
        return
            try TransferResult(
                data: FfiConverterTypeTransfer.read(from: &buf), 
                ticketId: FfiConverterString.read(from: &buf), 
                timestamp: FfiConverterTimestamp.read(from: &buf)
        )
    }

    public static func write(_ value: TransferResult, into buf: inout [UInt8]) {
        FfiConverterTypeTransfer.write(value.data, into: &buf)
        FfiConverterString.write(value.ticketId, into: &buf)
        FfiConverterTimestamp.write(value.timestamp, into: &buf)
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeTransferResult_lift(_ buf: RustBuffer) throws -> TransferResult {
    return try FfiConverterTypeTransferResult.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeTransferResult_lower(_ value: TransferResult) -> RustBuffer {
    return FfiConverterTypeTransferResult.lower(value)
}

// Note that we don't yet support `indirect` for enums.
// See https://github.com/mozilla/uniffi-rs/issues/396 for further discussion.

public enum AccountFilter: Equatable, Hashable {
    
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

public enum BalancesResponse {
    
    case result(result: AuthenticatedBalancesResult, session: Session?, connectionData: ConnectionData?
    )
    case dialog(context: DialogContext?, message: String?, image: Image?, input: DialogInput
    )
    case redirect(url: Url, context: ConfirmationContext
    )
    case redirectHandle(handle: String, context: ConfirmationContext
    )



}

#if compiler(>=6)
extension BalancesResponse: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeBalancesResponse: FfiConverterRustBuffer {
    typealias SwiftType = BalancesResponse

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> BalancesResponse {
        let variant: Int32 = try readInt(&buf)
        switch variant {
        
        case 1: return .result(result: try FfiConverterTypeAuthenticatedBalancesResult.read(from: &buf), session: try FfiConverterOptionTypeSession.read(from: &buf), connectionData: try FfiConverterOptionTypeConnectionData.read(from: &buf)
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

    public static func write(_ value: BalancesResponse, into buf: inout [UInt8]) {
        switch value {
        
        
        case let .result(result,session,connectionData):
            writeInt(&buf, Int32(1))
            FfiConverterTypeAuthenticatedBalancesResult.write(result, into: &buf)
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
public func FfiConverterTypeBalancesResponse_lift(_ buf: RustBuffer) throws -> BalancesResponse {
    return try FfiConverterTypeBalancesResponse.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeBalancesResponse_lower(_ value: BalancesResponse) -> RustBuffer {
    return FfiConverterTypeBalancesResponse.lower(value)
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

public enum DialogInput: Equatable, Hashable {
    
    /**
     * Just a primary action to confirm the dialog.
     */
    case confirmation(
        /**
         * Context object that can be used to confirm the dialog.
         */context: ConfirmationContext, 
        /**
         * If polling is acceptable, a delay in seconds is specified for which the client has to wait before automatically confirming.
         */pollingDelaySecs: UInt32?
    )
    /**
     * A selection of options the user can choose from.
     */
    case selection(
        /**
         * Options are meant to be rendered e.g. as radio buttons where the user must select exactly
         * one to for a confirmation button to get enabled. Another example for an implementation is
         * one button per option that immediately confirms the selection.
         */options: [DialogOption], 
        /**
         * Context object that can be used to respond to the dialog.
         */context: InputContext
    )
    /**
     * An input field.
     */
    case field(
        /**
         * Type that may be used for showing hints or dedicated keyboard layouts and for applying input restrictions or validation.
         */type: InputType, 
        /**
         * Indicates if the input should be masked.
         */secrecyLevel: SecrecyLevel, 
        /**
         * Minimal length to allow.
         */minLength: UInt32?, 
        /**
         * Maximum length to allow.
         */maxLength: UInt32?, 
        /**
         * Context object that can be used to respond to the dialog.
         */context: InputContext
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
        
        case 1: return .confirmation(context: try FfiConverterTypeConfirmationContext.read(from: &buf), pollingDelaySecs: try FfiConverterOptionUInt32.read(from: &buf)
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
        
        
        case let .confirmation(context,pollingDelaySecs):
            writeInt(&buf, Int32(1))
            FfiConverterTypeConfirmationContext.write(context, into: &buf)
            FfiConverterOptionUInt32.write(pollingDelaySecs, into: &buf)
            
        
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


// Note that we don't yet support `indirect` for enums.
// See https://github.com/mozilla/uniffi-rs/issues/396 for further discussion.
/**
 * Filters for the connection lookup
 *
 * String filters look for the given value anywhere in the related field, case-insensitive.
 */

public enum SearchFilter: Equatable, Hashable {
    
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


// Note that we don't yet support `indirect` for enums.
// See https://github.com/mozilla/uniffi-rs/issues/396 for further discussion.
/**
 * Response from YAXI Open Banking services.
 *
 * The response either carries an authenticated result
 * or an interrupt (i.e. a dialog or redirect for the user).
 */

public enum TransferResponse {
    
    case result(result: AuthenticatedTransferResult, session: Session?, connectionData: ConnectionData?
    )
    case dialog(context: DialogContext?, message: String?, image: Image?, input: DialogInput
    )
    case redirect(url: Url, context: ConfirmationContext
    )
    case redirectHandle(handle: String, context: ConfirmationContext
    )



}

#if compiler(>=6)
extension TransferResponse: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeTransferResponse: FfiConverterRustBuffer {
    typealias SwiftType = TransferResponse

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> TransferResponse {
        let variant: Int32 = try readInt(&buf)
        switch variant {
        
        case 1: return .result(result: try FfiConverterTypeAuthenticatedTransferResult.read(from: &buf), session: try FfiConverterOptionTypeSession.read(from: &buf), connectionData: try FfiConverterOptionTypeConnectionData.read(from: &buf)
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

    public static func write(_ value: TransferResponse, into buf: inout [UInt8]) {
        switch value {
        
        
        case let .result(result,session,connectionData):
            writeInt(&buf, Int32(1))
            FfiConverterTypeAuthenticatedTransferResult.write(result, into: &buf)
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
public func FfiConverterTypeTransferResponse_lift(_ buf: RustBuffer) throws -> TransferResponse {
    return try FfiConverterTypeTransferResponse.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeTransferResponse_lower(_ value: TransferResponse) -> RustBuffer {
    return FfiConverterTypeTransferResponse.lower(value)
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
fileprivate struct FfiConverterOptionBool: FfiConverterRustBuffer {
    typealias SwiftType = Bool?

    public static func write(_ value: SwiftType, into buf: inout [UInt8]) {
        guard let value = value else {
            writeInt(&buf, Int8(0))
            return
        }
        writeInt(&buf, Int8(1))
        FfiConverterBool.write(value, into: &buf)
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> SwiftType {
        switch try readInt(&buf) as Int8 {
        case 0: return nil
        case 1: return try FfiConverterBool.read(from: &buf)
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
fileprivate struct FfiConverterOptionTypeDateTime: FfiConverterRustBuffer {
    typealias SwiftType = DateTime?

    public static func write(_ value: SwiftType, into buf: inout [UInt8]) {
        guard let value = value else {
            writeInt(&buf, Int8(0))
            return
        }
        writeInt(&buf, Int8(1))
        FfiConverterTypeDateTime.write(value, into: &buf)
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> SwiftType {
        switch try readInt(&buf) as Int8 {
        case 0: return nil
        case 1: return try FfiConverterTypeDateTime.read(from: &buf)
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
fileprivate struct FfiConverterSequenceTypeAccountReference: FfiConverterRustBuffer {
    typealias SwiftType = [AccountReference]

    public static func write(_ value: [AccountReference], into buf: inout [UInt8]) {
        let len = Int32(value.count)
        writeInt(&buf, len)
        for item in value {
            FfiConverterTypeAccountReference.write(item, into: &buf)
        }
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> [AccountReference] {
        let len: Int32 = try readInt(&buf)
        var seq = [AccountReference]()
        seq.reserveCapacity(Int(len))
        for _ in 0 ..< len {
            seq.append(try FfiConverterTypeAccountReference.read(from: &buf))
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
fileprivate struct FfiConverterSequenceTypeTransferDetails: FfiConverterRustBuffer {
    typealias SwiftType = [TransferDetails]

    public static func write(_ value: [TransferDetails], into buf: inout [UInt8]) {
        let len = Int32(value.count)
        writeInt(&buf, len)
        for item in value {
            FfiConverterTypeTransferDetails.write(item, into: &buf)
        }
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> [TransferDetails] {
        let len: Int32 = try readInt(&buf)
        var seq = [TransferDetails]()
        seq.reserveCapacity(Int(len))
        for _ in 0 ..< len {
            seq.append(try FfiConverterTypeTransferDetails.read(from: &buf))
        }
        return seq
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

private let UNIFFI_RUST_FUTURE_POLL_READY: Int8 = 0
private let UNIFFI_RUST_FUTURE_POLL_WAKE: Int8 = 1

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
                { handle, pollResult in
                    uniffiFutureContinuationCallback(handle: handle, pollResult: pollResult)
                },
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
    let bindings_contract_version = 30
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
    if (uniffi_routex_client_uniffi_checksum_method_authenticatedbalancesresult_jwt() != 13676) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_authenticatedbalancesresult_to_data() != 24841) {
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
    if (uniffi_routex_client_uniffi_checksum_method_authenticatedtransferresult_jwt() != 23904) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_authenticatedtransferresult_to_data() != 2336) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_accounts() != 42833) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_balances() != 39399) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_collect_payment() != 15899) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_confirm_accounts() != 2256) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_confirm_balances() != 27344) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_confirm_collect_payment() != 38594) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_confirm_transactions() != 54091) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_confirm_transfer() != 21005) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_info() != 44429) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_register_redirect_uri() != 3136) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_respond_accounts() != 27191) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_respond_balances() != 45973) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_respond_collect_payment() != 5835) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_respond_transactions() != 18466) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_respond_transfer() != 64431) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_search() != 25248) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_set_redirect_uri() != 22586) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_settle_key() != 17822) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_system_version() != 42451) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_trace() != 49199) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_trace_id() != 58761) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_transactions() != 38307) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_method_routexclient_transfer() != 29451) {
        return InitializationResult.apiChecksumMismatch
    }
    if (uniffi_routex_client_uniffi_checksum_constructor_routexclient_new() != 13848) {
        return InitializationResult.apiChecksumMismatch
    }

    uniffiEnsureRoutexApiInitialized()
    uniffiEnsureRoutexClientCommonInitialized()
    uniffiEnsureRoutexModelsInitialized()
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