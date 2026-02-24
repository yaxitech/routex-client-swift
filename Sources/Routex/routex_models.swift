// swiftlint:disable all
import Foundation

// Depending on the consumer's build setup, the low-level FFI code
// might be in a separate module, or it might be compiled inline into
// this module. This is a bit of light hackery to work with both.
#if canImport(routex_modelsFFI)
import routex_modelsFFI
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
        try! rustCall { ffi_routex_models_rustbuffer_from_bytes(ForeignBytes(bufferPointer: ptr), $0) }
    }

    // Frees the buffer in place.
    // The buffer must not be used after this is called.
    func deallocate() {
        try! rustCall { ffi_routex_models_rustbuffer_free(self, $0) }
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
    uniffiEnsureRoutexModelsInitialized()
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


public struct Amount: Equatable, Hashable {
    /**
     * ISO 4217 Alpha 3 currency code.
     */
    public var currency: String
    public var amount: Decimal

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(
        /**
         * ISO 4217 Alpha 3 currency code.
         */currency: String, amount: Decimal) {
        self.currency = currency
        self.amount = amount
    }

    

    
}

#if compiler(>=6)
extension Amount: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeAmount: FfiConverterRustBuffer {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> Amount {
        return
            try Amount(
                currency: FfiConverterString.read(from: &buf), 
                amount: FfiConverterTypeDecimal.read(from: &buf)
        )
    }

    public static func write(_ value: Amount, into buf: inout [UInt8]) {
        FfiConverterString.write(value.currency, into: &buf)
        FfiConverterTypeDecimal.write(value.amount, into: &buf)
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAmount_lift(_ buf: RustBuffer) throws -> Amount {
    return try FfiConverterTypeAmount.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAmount_lower(_ value: Amount) -> RustBuffer {
    return FfiConverterTypeAmount.lower(value)
}


/**
 * Requirements for user identifier and password.
 */
public struct CredentialsModel: Equatable, Hashable {
    /**
     * A full set of credentials may be provided to support fully embedded authentication (including scraped redirects).
     */
    public var full: Bool
    /**
     * Only a user identifier without a password may be provided.
     * This is typically the case for decoupled authentication where the user e.g. authorizes access in a mobile application.
     * Note that if password-less authentication fails (e.g. as no device for decoupled authentication is set up for the user and
     * a redirect is not supported), an error is returned and the transaction has to get restarted with a full set of credentials.
     */
    public var userId: Bool
    /**
     * Credentials are not required. The user will provide them to the service provider during a redirect.
     */
    public var none: Bool

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(
        /**
         * A full set of credentials may be provided to support fully embedded authentication (including scraped redirects).
         */full: Bool, 
        /**
         * Only a user identifier without a password may be provided.
         * This is typically the case for decoupled authentication where the user e.g. authorizes access in a mobile application.
         * Note that if password-less authentication fails (e.g. as no device for decoupled authentication is set up for the user and
         * a redirect is not supported), an error is returned and the transaction has to get restarted with a full set of credentials.
         */userId: Bool, 
        /**
         * Credentials are not required. The user will provide them to the service provider during a redirect.
         */none: Bool) {
        self.full = full
        self.userId = userId
        self.none = none
    }

    

    
}

#if compiler(>=6)
extension CredentialsModel: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeCredentialsModel: FfiConverterRustBuffer {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> CredentialsModel {
        return
            try CredentialsModel(
                full: FfiConverterBool.read(from: &buf), 
                userId: FfiConverterBool.read(from: &buf), 
                none: FfiConverterBool.read(from: &buf)
        )
    }

    public static func write(_ value: CredentialsModel, into buf: inout [UInt8]) {
        FfiConverterBool.write(value.full, into: &buf)
        FfiConverterBool.write(value.userId, into: &buf)
        FfiConverterBool.write(value.none, into: &buf)
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeCredentialsModel_lift(_ buf: RustBuffer) throws -> CredentialsModel {
    return try FfiConverterTypeCredentialsModel.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeCredentialsModel_lower(_ value: CredentialsModel) -> RustBuffer {
    return FfiConverterTypeCredentialsModel.lower(value)
}


public struct CreditorAddress: Equatable, Hashable {
    public var townName: String
    public var country: CountryCode

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(townName: String, country: CountryCode) {
        self.townName = townName
        self.country = country
    }

    

    
}

#if compiler(>=6)
extension CreditorAddress: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeCreditorAddress: FfiConverterRustBuffer {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> CreditorAddress {
        return
            try CreditorAddress(
                townName: FfiConverterString.read(from: &buf), 
                country: FfiConverterTypeCountryCode.read(from: &buf)
        )
    }

    public static func write(_ value: CreditorAddress, into buf: inout [UInt8]) {
        FfiConverterString.write(value.townName, into: &buf)
        FfiConverterTypeCountryCode.write(value.country, into: &buf)
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeCreditorAddress_lift(_ buf: RustBuffer) throws -> CreditorAddress {
    return try FfiConverterTypeCreditorAddress.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeCreditorAddress_lower(_ value: CreditorAddress) -> RustBuffer {
    return FfiConverterTypeCreditorAddress.lower(value)
}


/**
 * A dialog option.
 */
public struct DialogOption: Equatable, Hashable {
    public var key: String
    public var label: String
    public var explanation: String?

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(key: String, label: String, explanation: String? = nil) {
        self.key = key
        self.label = label
        self.explanation = explanation
    }

    

    
}

#if compiler(>=6)
extension DialogOption: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeDialogOption: FfiConverterRustBuffer {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> DialogOption {
        return
            try DialogOption(
                key: FfiConverterString.read(from: &buf), 
                label: FfiConverterString.read(from: &buf), 
                explanation: FfiConverterOptionString.read(from: &buf)
        )
    }

    public static func write(_ value: DialogOption, into buf: inout [UInt8]) {
        FfiConverterString.write(value.key, into: &buf)
        FfiConverterString.write(value.label, into: &buf)
        FfiConverterOptionString.write(value.explanation, into: &buf)
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeDialogOption_lift(_ buf: RustBuffer) throws -> DialogOption {
    return try FfiConverterTypeDialogOption.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeDialogOption_lower(_ value: DialogOption) -> RustBuffer {
    return FfiConverterTypeDialogOption.lower(value)
}


public struct Fee: Equatable, Hashable {
    /**
     * Amount of the fee.
     */
    public var amount: Amount
    /**
     * ISO 20022 `ExternalChargeType1Code` for the fee.
     */
    public var kind: String?
    /**
     * ISO 20022 `BICFIIdentifier` of the agent to whom the charges are due.
     */
    public var bic: String?

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(
        /**
         * Amount of the fee.
         */amount: Amount, 
        /**
         * ISO 20022 `ExternalChargeType1Code` for the fee.
         */kind: String? = nil, 
        /**
         * ISO 20022 `BICFIIdentifier` of the agent to whom the charges are due.
         */bic: String? = nil) {
        self.amount = amount
        self.kind = kind
        self.bic = bic
    }

    

    
}

#if compiler(>=6)
extension Fee: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeFee: FfiConverterRustBuffer {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> Fee {
        return
            try Fee(
                amount: FfiConverterTypeAmount.read(from: &buf), 
                kind: FfiConverterOptionString.read(from: &buf), 
                bic: FfiConverterOptionString.read(from: &buf)
        )
    }

    public static func write(_ value: Fee, into buf: inout [UInt8]) {
        FfiConverterTypeAmount.write(value.amount, into: &buf)
        FfiConverterOptionString.write(value.kind, into: &buf)
        FfiConverterOptionString.write(value.bic, into: &buf)
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeFee_lift(_ buf: RustBuffer) throws -> Fee {
    return try FfiConverterTypeFee.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeFee_lower(_ value: Fee) -> RustBuffer {
    return FfiConverterTypeFee.lower(value)
}


/**
 * Image data for a dialog.
 */
public struct Image: Equatable, Hashable {
    public var mimeType: String
    /**
     * Binary data in the format defined by `mime_type`.
     */
    public var data: Bytes
    /**
     * HHD_UC data block
     *
     * In cases where the ASPSP provides HHD_UC data for optical coupling with a HandHeld-Device
     * for the generation of an OTP, especially for an HHD_OPT animated graphic, the raw HHD_UC
     * data stream is provided here.
     *
     * The publicly available document "HandHeld-Device (HHD) for the generation of an OTP HHD
     * enhancement for optical interfaces" describes how to implement the animated graphic for
     * HHD_OPT in section C. `data` provides a pre-rendered animated GIF
     * to be presented with a width of 62.5 mm.
     */
    public var hhdUcData: Bytes?

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(mimeType: String, 
        /**
         * Binary data in the format defined by `mime_type`.
         */data: Bytes, 
        /**
         * HHD_UC data block
         *
         * In cases where the ASPSP provides HHD_UC data for optical coupling with a HandHeld-Device
         * for the generation of an OTP, especially for an HHD_OPT animated graphic, the raw HHD_UC
         * data stream is provided here.
         *
         * The publicly available document "HandHeld-Device (HHD) for the generation of an OTP HHD
         * enhancement for optical interfaces" describes how to implement the animated graphic for
         * HHD_OPT in section C. `data` provides a pre-rendered animated GIF
         * to be presented with a width of 62.5 mm.
         */hhdUcData: Bytes? = nil) {
        self.mimeType = mimeType
        self.data = data
        self.hhdUcData = hhdUcData
    }

    

    
}

#if compiler(>=6)
extension Image: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeImage: FfiConverterRustBuffer {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> Image {
        return
            try Image(
                mimeType: FfiConverterString.read(from: &buf), 
                data: FfiConverterTypeBytes.read(from: &buf), 
                hhdUcData: FfiConverterOptionTypeBytes.read(from: &buf)
        )
    }

    public static func write(_ value: Image, into buf: inout [UInt8]) {
        FfiConverterString.write(value.mimeType, into: &buf)
        FfiConverterTypeBytes.write(value.data, into: &buf)
        FfiConverterOptionTypeBytes.write(value.hhdUcData, into: &buf)
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeImage_lift(_ buf: RustBuffer) throws -> Image {
    return try FfiConverterTypeImage.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeImage_lower(_ value: Image) -> RustBuffer {
    return FfiConverterTypeImage.lower(value)
}

// Note that we don't yet support `indirect` for enums.
// See https://github.com/mozilla/uniffi-rs/issues/396 for further discussion.

public enum AccountStatus: Equatable, Hashable {
    
    case available
    case terminated
    case blocked





}

#if compiler(>=6)
extension AccountStatus: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeAccountStatus: FfiConverterRustBuffer {
    typealias SwiftType = AccountStatus

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> AccountStatus {
        let variant: Int32 = try readInt(&buf)
        switch variant {
        
        case 1: return .available
        
        case 2: return .terminated
        
        case 3: return .blocked
        
        default: throw UniffiInternalError.unexpectedEnumCase
        }
    }

    public static func write(_ value: AccountStatus, into buf: inout [UInt8]) {
        switch value {
        
        
        case .available:
            writeInt(&buf, Int32(1))
        
        
        case .terminated:
            writeInt(&buf, Int32(2))
        
        
        case .blocked:
            writeInt(&buf, Int32(3))
        
        }
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAccountStatus_lift(_ buf: RustBuffer) throws -> AccountStatus {
    return try FfiConverterTypeAccountStatus.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAccountStatus_lower(_ value: AccountStatus) -> RustBuffer {
    return FfiConverterTypeAccountStatus.lower(value)
}


// Note that we don't yet support `indirect` for enums.
// See https://github.com/mozilla/uniffi-rs/issues/396 for further discussion.

public enum AccountType: Equatable, Hashable {
    
    /**
     * Account used to post debits and credits.
     * ISO 20022 ExternalCashAccountType1Code CACC.
     */
    case current
    /**
     * Account used for credit card payments.
     * ISO 20022 ExternalCashAccountType1Code CARD.
     */
    case card
    /**
     * Account used for savings.
     * ISO 20022 ExternalCashAccountType1Code SVGS.
     */
    case savings
    /**
     * Account used for call money.
     * No dedicated ISO 20022 code (falls into SVGS).
     */
    case callMoney
    /**
     * Account used for time deposits.
     * No dedicated ISO 20022 code (falls into SVGS).
     */
    case timeDeposit
    /**
     * Account used for loans.
     * ISO 20022 ExternalCashAccountType1Code LOAN.
     */
    case loan
    case securities
    case insurance
    case commerce
    case rewards





}

#if compiler(>=6)
extension AccountType: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeAccountType: FfiConverterRustBuffer {
    typealias SwiftType = AccountType

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> AccountType {
        let variant: Int32 = try readInt(&buf)
        switch variant {
        
        case 1: return .current
        
        case 2: return .card
        
        case 3: return .savings
        
        case 4: return .callMoney
        
        case 5: return .timeDeposit
        
        case 6: return .loan
        
        case 7: return .securities
        
        case 8: return .insurance
        
        case 9: return .commerce
        
        case 10: return .rewards
        
        default: throw UniffiInternalError.unexpectedEnumCase
        }
    }

    public static func write(_ value: AccountType, into buf: inout [UInt8]) {
        switch value {
        
        
        case .current:
            writeInt(&buf, Int32(1))
        
        
        case .card:
            writeInt(&buf, Int32(2))
        
        
        case .savings:
            writeInt(&buf, Int32(3))
        
        
        case .callMoney:
            writeInt(&buf, Int32(4))
        
        
        case .timeDeposit:
            writeInt(&buf, Int32(5))
        
        
        case .loan:
            writeInt(&buf, Int32(6))
        
        
        case .securities:
            writeInt(&buf, Int32(7))
        
        
        case .insurance:
            writeInt(&buf, Int32(8))
        
        
        case .commerce:
            writeInt(&buf, Int32(9))
        
        
        case .rewards:
            writeInt(&buf, Int32(10))
        
        }
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAccountType_lift(_ buf: RustBuffer) throws -> AccountType {
    return try FfiConverterTypeAccountType.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAccountType_lower(_ value: AccountType) -> RustBuffer {
    return FfiConverterTypeAccountType.lower(value)
}


// Note that we don't yet support `indirect` for enums.
// See https://github.com/mozilla/uniffi-rs/issues/396 for further discussion.

public enum ChargeBearer: Equatable, Hashable {
    
    case borneByDebtor
    case borneByCreditor
    case shared
    case followingServiceLevel





}

#if compiler(>=6)
extension ChargeBearer: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeChargeBearer: FfiConverterRustBuffer {
    typealias SwiftType = ChargeBearer

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> ChargeBearer {
        let variant: Int32 = try readInt(&buf)
        switch variant {
        
        case 1: return .borneByDebtor
        
        case 2: return .borneByCreditor
        
        case 3: return .shared
        
        case 4: return .followingServiceLevel
        
        default: throw UniffiInternalError.unexpectedEnumCase
        }
    }

    public static func write(_ value: ChargeBearer, into buf: inout [UInt8]) {
        switch value {
        
        
        case .borneByDebtor:
            writeInt(&buf, Int32(1))
        
        
        case .borneByCreditor:
            writeInt(&buf, Int32(2))
        
        
        case .shared:
            writeInt(&buf, Int32(3))
        
        
        case .followingServiceLevel:
            writeInt(&buf, Int32(4))
        
        }
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeChargeBearer_lift(_ buf: RustBuffer) throws -> ChargeBearer {
    return try FfiConverterTypeChargeBearer.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeChargeBearer_lower(_ value: ChargeBearer) -> RustBuffer {
    return FfiConverterTypeChargeBearer.lower(value)
}


// Note that we don't yet support `indirect` for enums.
// See https://github.com/mozilla/uniffi-rs/issues/396 for further discussion.
/**
 * Context of a user dialog.
 */

public enum DialogContext: Equatable, Hashable {
    
    /**
     * SCA or TAN process.
     *
     * There are multiple cases, distinguishable by the [`DialogInput`]:
     * - [`DialogInput::Confirmation`]: Decoupled process (e.g. confirmation in a SCA app).
     * - [`DialogInput::Selection`]: TAN method selection.
     * - [`DialogInput::Field`]: TAN entry.
     */
    case sca
    /**
     * Account selection.
     *
     * A [`DialogInput::Selection`] gets returned with this context when an account has to be selected.
     * Note that there might be just a single option that may be chosen automatically without user interaction.
     */
    case accounts
    /**
     * Pending redirect confirmation.
     *
     * A [`DialogInput::Confirmation`] gets returned with this context when a redirect got confirmed but no result is known yet.
     */
    case redirect
    /**
     * Pending SCT Inst payment.
     *
     * A [`DialogInput::Confirmation`] gets returned with this context when an SCT Inst payment has been initialized and not reached the final status yet.
     */
    case paymentStatus
    /**
     * Verification of Payee confirmation.
     *
     * A [`DialogInput::Confirmation`] gets returned with this context when an explicit confirmation of the creditor is required due to a name mismatch.
     * Note that this confirmation has legal implications, releasing the bank from liabilities in case of the transfer to an unintended receiver due to incorrect creditor data.
     */
    case vopConfirmation
    /**
     * Pending Verification of Payee check.
     *
     * A [`DialogInput::Confirmation`] gets returned with this context when a Verification of Payee check for a bulk payment is still pending.
     */
    case vopCheck





}

#if compiler(>=6)
extension DialogContext: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeDialogContext: FfiConverterRustBuffer {
    typealias SwiftType = DialogContext

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> DialogContext {
        let variant: Int32 = try readInt(&buf)
        switch variant {
        
        case 1: return .sca
        
        case 2: return .accounts
        
        case 3: return .redirect
        
        case 4: return .paymentStatus
        
        case 5: return .vopConfirmation
        
        case 6: return .vopCheck
        
        default: throw UniffiInternalError.unexpectedEnumCase
        }
    }

    public static func write(_ value: DialogContext, into buf: inout [UInt8]) {
        switch value {
        
        
        case .sca:
            writeInt(&buf, Int32(1))
        
        
        case .accounts:
            writeInt(&buf, Int32(2))
        
        
        case .redirect:
            writeInt(&buf, Int32(3))
        
        
        case .paymentStatus:
            writeInt(&buf, Int32(4))
        
        
        case .vopConfirmation:
            writeInt(&buf, Int32(5))
        
        
        case .vopCheck:
            writeInt(&buf, Int32(6))
        
        }
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeDialogContext_lift(_ buf: RustBuffer) throws -> DialogContext {
    return try FfiConverterTypeDialogContext.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeDialogContext_lower(_ value: DialogContext) -> RustBuffer {
    return FfiConverterTypeDialogContext.lower(value)
}


// Note that we don't yet support `indirect` for enums.
// See https://github.com/mozilla/uniffi-rs/issues/396 for further discussion.
/**
 * Type of an input field.
 */

public enum InputType: Equatable, Hashable {
    
    case date
    case email
    case number
    case phone
    case text





}

#if compiler(>=6)
extension InputType: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeInputType: FfiConverterRustBuffer {
    typealias SwiftType = InputType

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> InputType {
        let variant: Int32 = try readInt(&buf)
        switch variant {
        
        case 1: return .date
        
        case 2: return .email
        
        case 3: return .number
        
        case 4: return .phone
        
        case 5: return .text
        
        default: throw UniffiInternalError.unexpectedEnumCase
        }
    }

    public static func write(_ value: InputType, into buf: inout [UInt8]) {
        switch value {
        
        
        case .date:
            writeInt(&buf, Int32(1))
        
        
        case .email:
            writeInt(&buf, Int32(2))
        
        
        case .number:
            writeInt(&buf, Int32(3))
        
        
        case .phone:
            writeInt(&buf, Int32(4))
        
        
        case .text:
            writeInt(&buf, Int32(5))
        
        }
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeInputType_lift(_ buf: RustBuffer) throws -> InputType {
    return try FfiConverterTypeInputType.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeInputType_lower(_ value: InputType) -> RustBuffer {
    return FfiConverterTypeInputType.lower(value)
}


// Note that we don't yet support `indirect` for enums.
// See https://github.com/mozilla/uniffi-rs/issues/396 for further discussion.

public enum PaymentErrorCode: Equatable, Hashable {
    
    case limitExceeded
    case insufficientFunds





}

#if compiler(>=6)
extension PaymentErrorCode: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypePaymentErrorCode: FfiConverterRustBuffer {
    typealias SwiftType = PaymentErrorCode

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> PaymentErrorCode {
        let variant: Int32 = try readInt(&buf)
        switch variant {
        
        case 1: return .limitExceeded
        
        case 2: return .insufficientFunds
        
        default: throw UniffiInternalError.unexpectedEnumCase
        }
    }

    public static func write(_ value: PaymentErrorCode, into buf: inout [UInt8]) {
        switch value {
        
        
        case .limitExceeded:
            writeInt(&buf, Int32(1))
        
        
        case .insufficientFunds:
            writeInt(&buf, Int32(2))
        
        }
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypePaymentErrorCode_lift(_ buf: RustBuffer) throws -> PaymentErrorCode {
    return try FfiConverterTypePaymentErrorCode.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypePaymentErrorCode_lower(_ value: PaymentErrorCode) -> RustBuffer {
    return FfiConverterTypePaymentErrorCode.lower(value)
}


// Note that we don't yet support `indirect` for enums.
// See https://github.com/mozilla/uniffi-rs/issues/396 for further discussion.

public enum PaymentProduct: Equatable, Hashable {
    
    /**
     * SEPA Credit Transfer (SCT) in EUR
     */
    case sepaCreditTransfer
    /**
     * SEPA Instant Credit Transfer (SCT Inst) in EUR
     */
    case sepaInstantCreditTransfer
    /**
     * Default SEPA Credit Transfer in EUR
     *
     * Tries SCT Inst with a fallback to SCT if this is supported.
     * Otherwise, SCT is used.
     */
    case defaultSepaCreditTransfer
    /**
     * International credit transfer outside of SEPA (typically SWIFT)
     */
    case crossBorderCreditTransfer
    /**
     * Domestic credit transfer in the domestic, non-EUR currency
     */
    case domesticCreditTransfer
    /**
     * Instant domestic credit transfer in the domestic, non-EUR currency
     */
    case domesticInstantCreditTransfer





}

#if compiler(>=6)
extension PaymentProduct: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypePaymentProduct: FfiConverterRustBuffer {
    typealias SwiftType = PaymentProduct

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> PaymentProduct {
        let variant: Int32 = try readInt(&buf)
        switch variant {
        
        case 1: return .sepaCreditTransfer
        
        case 2: return .sepaInstantCreditTransfer
        
        case 3: return .defaultSepaCreditTransfer
        
        case 4: return .crossBorderCreditTransfer
        
        case 5: return .domesticCreditTransfer
        
        case 6: return .domesticInstantCreditTransfer
        
        default: throw UniffiInternalError.unexpectedEnumCase
        }
    }

    public static func write(_ value: PaymentProduct, into buf: inout [UInt8]) {
        switch value {
        
        
        case .sepaCreditTransfer:
            writeInt(&buf, Int32(1))
        
        
        case .sepaInstantCreditTransfer:
            writeInt(&buf, Int32(2))
        
        
        case .defaultSepaCreditTransfer:
            writeInt(&buf, Int32(3))
        
        
        case .crossBorderCreditTransfer:
            writeInt(&buf, Int32(4))
        
        
        case .domesticCreditTransfer:
            writeInt(&buf, Int32(5))
        
        
        case .domesticInstantCreditTransfer:
            writeInt(&buf, Int32(6))
        
        }
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypePaymentProduct_lift(_ buf: RustBuffer) throws -> PaymentProduct {
    return try FfiConverterTypePaymentProduct.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypePaymentProduct_lower(_ value: PaymentProduct) -> RustBuffer {
    return FfiConverterTypePaymentProduct.lower(value)
}


// Note that we don't yet support `indirect` for enums.
// See https://github.com/mozilla/uniffi-rs/issues/396 for further discussion.

public enum ProviderErrorCode: Equatable, Hashable {
    
    case maintenance





}

#if compiler(>=6)
extension ProviderErrorCode: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeProviderErrorCode: FfiConverterRustBuffer {
    typealias SwiftType = ProviderErrorCode

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> ProviderErrorCode {
        let variant: Int32 = try readInt(&buf)
        switch variant {
        
        case 1: return .maintenance
        
        default: throw UniffiInternalError.unexpectedEnumCase
        }
    }

    public static func write(_ value: ProviderErrorCode, into buf: inout [UInt8]) {
        switch value {
        
        
        case .maintenance:
            writeInt(&buf, Int32(1))
        
        }
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeProviderErrorCode_lift(_ buf: RustBuffer) throws -> ProviderErrorCode {
    return try FfiConverterTypeProviderErrorCode.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeProviderErrorCode_lower(_ value: ProviderErrorCode) -> RustBuffer {
    return FfiConverterTypeProviderErrorCode.lower(value)
}


// Note that we don't yet support `indirect` for enums.
// See https://github.com/mozilla/uniffi-rs/issues/396 for further discussion.
/**
 * Level of secrecy for an input field.
 */

public enum SecrecyLevel: Equatable, Hashable {
    
    /**
     * The data is not a secret.
     */
    case plain
    /**
     * The data is a one-time password. This can usually be treated as
     * no secret but the implementer might still choose to mask the input.
     */
    case otp
    /**
     * The data is a secret password. Input must be masked.
     */
    case password





}

#if compiler(>=6)
extension SecrecyLevel: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeSecrecyLevel: FfiConverterRustBuffer {
    typealias SwiftType = SecrecyLevel

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> SecrecyLevel {
        let variant: Int32 = try readInt(&buf)
        switch variant {
        
        case 1: return .plain
        
        case 2: return .otp
        
        case 3: return .password
        
        default: throw UniffiInternalError.unexpectedEnumCase
        }
    }

    public static func write(_ value: SecrecyLevel, into buf: inout [UInt8]) {
        switch value {
        
        
        case .plain:
            writeInt(&buf, Int32(1))
        
        
        case .otp:
            writeInt(&buf, Int32(2))
        
        
        case .password:
            writeInt(&buf, Int32(3))
        
        }
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeSecrecyLevel_lift(_ buf: RustBuffer) throws -> SecrecyLevel {
    return try FfiConverterTypeSecrecyLevel.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeSecrecyLevel_lower(_ value: SecrecyLevel) -> RustBuffer {
    return FfiConverterTypeSecrecyLevel.lower(value)
}


// Note that we don't yet support `indirect` for enums.
// See https://github.com/mozilla/uniffi-rs/issues/396 for further discussion.

public enum ServiceBlockedCode: Equatable, Hashable {
    
    /**
     * Something is not set up for the user, e.g., there are no TAN methods.
     */
    case missingSetup
    /**
     * User attention is required via another channel. Typically the user needs to log into the Online Banking.
     */
    case actionRequired





}

#if compiler(>=6)
extension ServiceBlockedCode: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeServiceBlockedCode: FfiConverterRustBuffer {
    typealias SwiftType = ServiceBlockedCode

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> ServiceBlockedCode {
        let variant: Int32 = try readInt(&buf)
        switch variant {
        
        case 1: return .missingSetup
        
        case 2: return .actionRequired
        
        default: throw UniffiInternalError.unexpectedEnumCase
        }
    }

    public static func write(_ value: ServiceBlockedCode, into buf: inout [UInt8]) {
        switch value {
        
        
        case .missingSetup:
            writeInt(&buf, Int32(1))
        
        
        case .actionRequired:
            writeInt(&buf, Int32(2))
        
        }
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeServiceBlockedCode_lift(_ buf: RustBuffer) throws -> ServiceBlockedCode {
    return try FfiConverterTypeServiceBlockedCode.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeServiceBlockedCode_lower(_ value: ServiceBlockedCode) -> RustBuffer {
    return FfiConverterTypeServiceBlockedCode.lower(value)
}


// Note that we don't yet support `indirect` for enums.
// See https://github.com/mozilla/uniffi-rs/issues/396 for further discussion.

public enum TransactionStatus: Equatable, Hashable {
    
    /**
     * The transaction is expected / planned.
     */
    case pending
    /**
     * The transaction is booked to the account. This is typically the final state for most accounts.
     */
    case booked
    /**
     * The credit card transaction is booked and invoiced but not yet paid.
     */
    case invoiced
    /**
     * The credit card transaction is paid. This is typically the final state for card accounts.
     */
    case paid
    /**
     * The transaction has been canceled in some way.
     */
    case canceled





}

#if compiler(>=6)
extension TransactionStatus: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeTransactionStatus: FfiConverterRustBuffer {
    typealias SwiftType = TransactionStatus

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> TransactionStatus {
        let variant: Int32 = try readInt(&buf)
        switch variant {
        
        case 1: return .pending
        
        case 2: return .booked
        
        case 3: return .invoiced
        
        case 4: return .paid
        
        case 5: return .canceled
        
        default: throw UniffiInternalError.unexpectedEnumCase
        }
    }

    public static func write(_ value: TransactionStatus, into buf: inout [UInt8]) {
        switch value {
        
        
        case .pending:
            writeInt(&buf, Int32(1))
        
        
        case .booked:
            writeInt(&buf, Int32(2))
        
        
        case .invoiced:
            writeInt(&buf, Int32(3))
        
        
        case .paid:
            writeInt(&buf, Int32(4))
        
        
        case .canceled:
            writeInt(&buf, Int32(5))
        
        }
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeTransactionStatus_lift(_ buf: RustBuffer) throws -> TransactionStatus {
    return try FfiConverterTypeTransactionStatus.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeTransactionStatus_lower(_ value: TransactionStatus) -> RustBuffer {
    return FfiConverterTypeTransactionStatus.lower(value)
}


// Note that we don't yet support `indirect` for enums.
// See https://github.com/mozilla/uniffi-rs/issues/396 for further discussion.

public enum UnsupportedProductReason: Equatable, Hashable {
    
    /**
     * The amount is not allowed for the payment product.
     */
    case limit
    /**
     * The recipient is not capable to receive the payment product.
     */
    case recipient
    /**
     * Scheduled payments are not supported.
     */
    case scheduled





}

#if compiler(>=6)
extension UnsupportedProductReason: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeUnsupportedProductReason: FfiConverterRustBuffer {
    typealias SwiftType = UnsupportedProductReason

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> UnsupportedProductReason {
        let variant: Int32 = try readInt(&buf)
        switch variant {
        
        case 1: return .limit
        
        case 2: return .recipient
        
        case 3: return .scheduled
        
        default: throw UniffiInternalError.unexpectedEnumCase
        }
    }

    public static func write(_ value: UnsupportedProductReason, into buf: inout [UInt8]) {
        switch value {
        
        
        case .limit:
            writeInt(&buf, Int32(1))
        
        
        case .recipient:
            writeInt(&buf, Int32(2))
        
        
        case .scheduled:
            writeInt(&buf, Int32(3))
        
        }
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeUnsupportedProductReason_lift(_ buf: RustBuffer) throws -> UnsupportedProductReason {
    return try FfiConverterTypeUnsupportedProductReason.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeUnsupportedProductReason_lower(_ value: UnsupportedProductReason) -> RustBuffer {
    return FfiConverterTypeUnsupportedProductReason.lower(value)
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
fileprivate struct FfiConverterOptionTypeBytes: FfiConverterRustBuffer {
    typealias SwiftType = Bytes?

    public static func write(_ value: SwiftType, into buf: inout [UInt8]) {
        guard let value = value else {
            writeInt(&buf, Int8(0))
            return
        }
        writeInt(&buf, Int8(1))
        FfiConverterTypeBytes.write(value, into: &buf)
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> SwiftType {
        switch try readInt(&buf) as Int8 {
        case 0: return nil
        case 1: return try FfiConverterTypeBytes.read(from: &buf)
        default: throw UniffiInternalError.unexpectedOptionalTag
        }
    }
}


/**
 * Typealias from the type name used in the UDL file to the builtin type.  This
 * is needed because the UDL type name is used in function/method signatures.
 */
public typealias Bytes = Data

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeBytes: FfiConverter {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> Bytes {
        return try FfiConverterData.read(from: &buf)
    }

    public static func write(_ value: Bytes, into buf: inout [UInt8]) {
        return FfiConverterData.write(value, into: &buf)
    }

    public static func lift(_ value: RustBuffer) throws -> Bytes {
        return try FfiConverterData.lift(value)
    }

    public static func lower(_ value: Bytes) -> RustBuffer {
        return FfiConverterData.lower(value)
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeBytes_lift(_ value: RustBuffer) throws -> Bytes {
    return try FfiConverterTypeBytes.lift(value)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeBytes_lower(_ value: Bytes) -> RustBuffer {
    return FfiConverterTypeBytes.lower(value)
}



/**
 * Typealias from the type name used in the UDL file to the builtin type.  This
 * is needed because the UDL type name is used in function/method signatures.
 */
public typealias ConnectionId = String

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeConnectionId: FfiConverter {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> ConnectionId {
        return try FfiConverterString.read(from: &buf)
    }

    public static func write(_ value: ConnectionId, into buf: inout [UInt8]) {
        return FfiConverterString.write(value, into: &buf)
    }

    public static func lift(_ value: RustBuffer) throws -> ConnectionId {
        return try FfiConverterString.lift(value)
    }

    public static func lower(_ value: ConnectionId) -> RustBuffer {
        return FfiConverterString.lower(value)
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeConnectionId_lift(_ value: RustBuffer) throws -> ConnectionId {
    return try FfiConverterTypeConnectionId.lift(value)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeConnectionId_lower(_ value: ConnectionId) -> RustBuffer {
    return FfiConverterTypeConnectionId.lower(value)
}



/**
 * Typealias from the type name used in the UDL file to the builtin type.  This
 * is needed because the UDL type name is used in function/method signatures.
 */
public typealias CountryCode = String

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeCountryCode: FfiConverter {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> CountryCode {
        return try FfiConverterString.read(from: &buf)
    }

    public static func write(_ value: CountryCode, into buf: inout [UInt8]) {
        return FfiConverterString.write(value, into: &buf)
    }

    public static func lift(_ value: RustBuffer) throws -> CountryCode {
        return try FfiConverterString.lift(value)
    }

    public static func lower(_ value: CountryCode) -> RustBuffer {
        return FfiConverterString.lower(value)
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeCountryCode_lift(_ value: RustBuffer) throws -> CountryCode {
    return try FfiConverterTypeCountryCode.lift(value)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeCountryCode_lower(_ value: CountryCode) -> RustBuffer {
    return FfiConverterTypeCountryCode.lower(value)
}






#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeDecimal: FfiConverter {

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> Decimal {
        let builtinValue = try FfiConverterString.read(from: &buf)
        return Decimal.init(string: builtinValue)!
    }

    public static func write(_ value: Decimal, into buf: inout [UInt8]) {
        let builtinValue = String(describing: value)
        return FfiConverterString.write(builtinValue, into: &buf)
    }

    public static func lift(_ value: RustBuffer) throws -> Decimal {
        let builtinValue = try FfiConverterString.lift(value)
        return Decimal.init(string: builtinValue)!
    }

    public static func lower(_ value: Decimal) -> RustBuffer {
        let builtinValue = String(describing: value)
        return FfiConverterString.lower(builtinValue)
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeDecimal_lift(_ value: RustBuffer) throws -> Decimal {
    return try FfiConverterTypeDecimal.lift(value)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeDecimal_lower(_ value: Decimal) -> RustBuffer {
    return FfiConverterTypeDecimal.lower(value)
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
    let scaffolding_contract_version = ffi_routex_models_uniffi_contract_version()
    if bindings_contract_version != scaffolding_contract_version {
        return InitializationResult.contractVersionMismatch
    }

    return InitializationResult.ok
}()

// Make the ensure init function public so that other modules which have external type references to
// our types can call it.
public func uniffiEnsureRoutexModelsInitialized() {
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