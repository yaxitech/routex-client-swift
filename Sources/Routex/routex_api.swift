// swiftlint:disable all
import Foundation

// Depending on the consumer's build setup, the low-level FFI code
// might be in a separate module, or it might be compiled inline into
// this module. This is a bit of light hackery to work with both.
#if canImport(routex_apiFFI)
import routex_apiFFI
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
        try! rustCall { ffi_routex_api_rustbuffer_from_bytes(ForeignBytes(bufferPointer: ptr), $0) }
    }

    // Frees the buffer in place.
    // The buffer must not be used after this is called.
    func deallocate() {
        try! rustCall { ffi_routex_api_rustbuffer_free(self, $0) }
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
    uniffiEnsureRoutexApiInitialized()
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


public struct Account {
    /**
     * ISO 20022 IBAN2007Identifier.
     */
    public var iban: String?
    /**
     * Account number that is not an IBAN, e.g. ISO 20022 BBANIdentifier or primary account number (PAN) of a card account.
     */
    public var number: String?
    /**
     * ISO 20022 BICFIIdentifier.
     */
    public var bic: String?
    /**
     * National bank code.
     */
    public var bankCode: String?
    /**
     * ISO 4217 Alpha 3 currency code.
     */
    public var currency: String?
    /**
     * Name of account, assigned by ASPSP.
     */
    public var name: String?
    /**
     * Display name of account, assigned by PSU.
     */
    public var displayName: String?
    /**
     * Legal account owner.
     */
    public var ownerName: String?
    /**
     * Product name.
     */
    public var productName: String?
    /**
     * Account status.
     */
    public var status: AccountStatus?
    /**
     * Account type.
     */
    public var type: AccountType?

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(
        /**
         * ISO 20022 IBAN2007Identifier.
         */iban: String? = nil, 
        /**
         * Account number that is not an IBAN, e.g. ISO 20022 BBANIdentifier or primary account number (PAN) of a card account.
         */number: String? = nil, 
        /**
         * ISO 20022 BICFIIdentifier.
         */bic: String? = nil, 
        /**
         * National bank code.
         */bankCode: String? = nil, 
        /**
         * ISO 4217 Alpha 3 currency code.
         */currency: String? = nil, 
        /**
         * Name of account, assigned by ASPSP.
         */name: String? = nil, 
        /**
         * Display name of account, assigned by PSU.
         */displayName: String? = nil, 
        /**
         * Legal account owner.
         */ownerName: String? = nil, 
        /**
         * Product name.
         */productName: String? = nil, 
        /**
         * Account status.
         */status: AccountStatus? = nil, 
        /**
         * Account type.
         */type: AccountType? = nil) {
        self.iban = iban
        self.number = number
        self.bic = bic
        self.bankCode = bankCode
        self.currency = currency
        self.name = name
        self.displayName = displayName
        self.ownerName = ownerName
        self.productName = productName
        self.status = status
        self.type = type
    }
}

#if compiler(>=6)
extension Account: Sendable {}
#endif


extension Account: Equatable, Hashable {
    public static func ==(lhs: Account, rhs: Account) -> Bool {
        if lhs.iban != rhs.iban {
            return false
        }
        if lhs.number != rhs.number {
            return false
        }
        if lhs.bic != rhs.bic {
            return false
        }
        if lhs.bankCode != rhs.bankCode {
            return false
        }
        if lhs.currency != rhs.currency {
            return false
        }
        if lhs.name != rhs.name {
            return false
        }
        if lhs.displayName != rhs.displayName {
            return false
        }
        if lhs.ownerName != rhs.ownerName {
            return false
        }
        if lhs.productName != rhs.productName {
            return false
        }
        if lhs.status != rhs.status {
            return false
        }
        if lhs.type != rhs.type {
            return false
        }
        return true
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(iban)
        hasher.combine(number)
        hasher.combine(bic)
        hasher.combine(bankCode)
        hasher.combine(currency)
        hasher.combine(name)
        hasher.combine(displayName)
        hasher.combine(ownerName)
        hasher.combine(productName)
        hasher.combine(status)
        hasher.combine(type)
    }
}



#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeAccount: FfiConverterRustBuffer {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> Account {
        return
            try Account(
                iban: FfiConverterOptionString.read(from: &buf), 
                number: FfiConverterOptionString.read(from: &buf), 
                bic: FfiConverterOptionString.read(from: &buf), 
                bankCode: FfiConverterOptionString.read(from: &buf), 
                currency: FfiConverterOptionString.read(from: &buf), 
                name: FfiConverterOptionString.read(from: &buf), 
                displayName: FfiConverterOptionString.read(from: &buf), 
                ownerName: FfiConverterOptionString.read(from: &buf), 
                productName: FfiConverterOptionString.read(from: &buf), 
                status: FfiConverterOptionTypeAccountStatus.read(from: &buf), 
                type: FfiConverterOptionTypeAccountType.read(from: &buf)
        )
    }

    public static func write(_ value: Account, into buf: inout [UInt8]) {
        FfiConverterOptionString.write(value.iban, into: &buf)
        FfiConverterOptionString.write(value.number, into: &buf)
        FfiConverterOptionString.write(value.bic, into: &buf)
        FfiConverterOptionString.write(value.bankCode, into: &buf)
        FfiConverterOptionString.write(value.currency, into: &buf)
        FfiConverterOptionString.write(value.name, into: &buf)
        FfiConverterOptionString.write(value.displayName, into: &buf)
        FfiConverterOptionString.write(value.ownerName, into: &buf)
        FfiConverterOptionString.write(value.productName, into: &buf)
        FfiConverterOptionTypeAccountStatus.write(value.status, into: &buf)
        FfiConverterOptionTypeAccountType.write(value.type, into: &buf)
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAccount_lift(_ buf: RustBuffer) throws -> Account {
    return try FfiConverterTypeAccount.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAccount_lower(_ value: Account) -> RustBuffer {
    return FfiConverterTypeAccount.lower(value)
}


public struct AccountReference {
    public var id: AccountIdentifier
    public var currency: String?

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(id: AccountIdentifier, currency: String? = nil) {
        self.id = id
        self.currency = currency
    }
}

#if compiler(>=6)
extension AccountReference: Sendable {}
#endif


extension AccountReference: Equatable, Hashable {
    public static func ==(lhs: AccountReference, rhs: AccountReference) -> Bool {
        if lhs.id != rhs.id {
            return false
        }
        if lhs.currency != rhs.currency {
            return false
        }
        return true
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
        hasher.combine(currency)
    }
}



#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeAccountReference: FfiConverterRustBuffer {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> AccountReference {
        return
            try AccountReference(
                id: FfiConverterTypeAccountIdentifier.read(from: &buf), 
                currency: FfiConverterOptionString.read(from: &buf)
        )
    }

    public static func write(_ value: AccountReference, into buf: inout [UInt8]) {
        FfiConverterTypeAccountIdentifier.write(value.id, into: &buf)
        FfiConverterOptionString.write(value.currency, into: &buf)
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAccountReference_lift(_ buf: RustBuffer) throws -> AccountReference {
    return try FfiConverterTypeAccountReference.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAccountReference_lower(_ value: AccountReference) -> RustBuffer {
    return FfiConverterTypeAccountReference.lower(value)
}


public struct BatchData {
    /**
     * Number of transactions in the batch, if known.
     */
    public var numberOfTransactions: UInt32?
    /**
     * Details of transactions in the batch.
     *
     * Note that this does not necessarily match a given number of transactions.
     * It could be e.g. empty as no details are given or a single entry with common details on all transactions in the batch.
     */
    public var transactions: [BatchTransactionDetails]

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(
        /**
         * Number of transactions in the batch, if known.
         */numberOfTransactions: UInt32?, 
        /**
         * Details of transactions in the batch.
         *
         * Note that this does not necessarily match a given number of transactions.
         * It could be e.g. empty as no details are given or a single entry with common details on all transactions in the batch.
         */transactions: [BatchTransactionDetails]) {
        self.numberOfTransactions = numberOfTransactions
        self.transactions = transactions
    }
}

#if compiler(>=6)
extension BatchData: Sendable {}
#endif


extension BatchData: Equatable, Hashable {
    public static func ==(lhs: BatchData, rhs: BatchData) -> Bool {
        if lhs.numberOfTransactions != rhs.numberOfTransactions {
            return false
        }
        if lhs.transactions != rhs.transactions {
            return false
        }
        return true
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(numberOfTransactions)
        hasher.combine(transactions)
    }
}



#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeBatchData: FfiConverterRustBuffer {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> BatchData {
        return
            try BatchData(
                numberOfTransactions: FfiConverterOptionUInt32.read(from: &buf), 
                transactions: FfiConverterSequenceTypeBatchTransactionDetails.read(from: &buf)
        )
    }

    public static func write(_ value: BatchData, into buf: inout [UInt8]) {
        FfiConverterOptionUInt32.write(value.numberOfTransactions, into: &buf)
        FfiConverterSequenceTypeBatchTransactionDetails.write(value.transactions, into: &buf)
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeBatchData_lift(_ buf: RustBuffer) throws -> BatchData {
    return try FfiConverterTypeBatchData.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeBatchData_lower(_ value: BatchData) -> RustBuffer {
    return FfiConverterTypeBatchData.lower(value)
}


public struct BatchTransactionDetails {
    /**
     * Unique reference assigned by the account servicer.
     */
    public var accountServicerReference: String?
    /**
     * Unique identifier assigned by the sending party.
     */
    public var paymentId: String?
    /**
     * Unique identifier assigned by the first instructing agent.
     */
    public var transactionId: String?
    /**
     * Unique end-to-end identifier assigned by the initiating party.
     */
    public var endToEndId: String?
    /**
     * Mandate identifier.
     */
    public var mandateId: String?
    /**
     * SEPA creditor identifier.
     */
    public var creditorId: String?
    /**
     * Transaction amount as billed to the account.
     */
    public var amount: Amount?
    /**
     * Indicator for reversals.
     */
    public var reversal: Bool
    /**
     * Original amount of the transaction.
     */
    public var originalAmount: Amount?
    /**
     * Exchange rates.
     */
    public var exchanges: [ExchangeRate]
    /**
     * Any fees related to the transaction.
     */
    public var fees: [Fee]
    /**
     * Creditor data. In case of reversals this refers to the initial transaction.
     */
    public var creditor: Party?
    /**
     * Debtor data. In case of reversals this refers to the initial transaction.
     */
    public var debtor: Party?
    /**
     * Remittance (purpose).
     */
    public var remittanceInformation: [String]
    /**
     * ISO 20022 ExternalPurpose1Code.
     */
    public var purposeCode: String?
    /**
     * Bank Transaction Codes.
     */
    public var bankTransactionCodes: [BankTransactionCode]
    /**
     * Additional information attached to the transaction.
     *
     * This might be a proprietary, localized, human-readable long text corresponding to some machine-readable bank transaction code that is not directly provided by the bank.
     */
    public var additionalInformation: String?

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(
        /**
         * Unique reference assigned by the account servicer.
         */accountServicerReference: String? = nil, 
        /**
         * Unique identifier assigned by the sending party.
         */paymentId: String? = nil, 
        /**
         * Unique identifier assigned by the first instructing agent.
         */transactionId: String? = nil, 
        /**
         * Unique end-to-end identifier assigned by the initiating party.
         */endToEndId: String? = nil, 
        /**
         * Mandate identifier.
         */mandateId: String? = nil, 
        /**
         * SEPA creditor identifier.
         */creditorId: String? = nil, 
        /**
         * Transaction amount as billed to the account.
         */amount: Amount? = nil, 
        /**
         * Indicator for reversals.
         */reversal: Bool = false, 
        /**
         * Original amount of the transaction.
         */originalAmount: Amount? = nil, 
        /**
         * Exchange rates.
         */exchanges: [ExchangeRate] = [], 
        /**
         * Any fees related to the transaction.
         */fees: [Fee] = [], 
        /**
         * Creditor data. In case of reversals this refers to the initial transaction.
         */creditor: Party? = nil, 
        /**
         * Debtor data. In case of reversals this refers to the initial transaction.
         */debtor: Party? = nil, 
        /**
         * Remittance (purpose).
         */remittanceInformation: [String] = [], 
        /**
         * ISO 20022 ExternalPurpose1Code.
         */purposeCode: String? = nil, 
        /**
         * Bank Transaction Codes.
         */bankTransactionCodes: [BankTransactionCode] = [], 
        /**
         * Additional information attached to the transaction.
         *
         * This might be a proprietary, localized, human-readable long text corresponding to some machine-readable bank transaction code that is not directly provided by the bank.
         */additionalInformation: String? = nil) {
        self.accountServicerReference = accountServicerReference
        self.paymentId = paymentId
        self.transactionId = transactionId
        self.endToEndId = endToEndId
        self.mandateId = mandateId
        self.creditorId = creditorId
        self.amount = amount
        self.reversal = reversal
        self.originalAmount = originalAmount
        self.exchanges = exchanges
        self.fees = fees
        self.creditor = creditor
        self.debtor = debtor
        self.remittanceInformation = remittanceInformation
        self.purposeCode = purposeCode
        self.bankTransactionCodes = bankTransactionCodes
        self.additionalInformation = additionalInformation
    }
}

#if compiler(>=6)
extension BatchTransactionDetails: Sendable {}
#endif


extension BatchTransactionDetails: Equatable, Hashable {
    public static func ==(lhs: BatchTransactionDetails, rhs: BatchTransactionDetails) -> Bool {
        if lhs.accountServicerReference != rhs.accountServicerReference {
            return false
        }
        if lhs.paymentId != rhs.paymentId {
            return false
        }
        if lhs.transactionId != rhs.transactionId {
            return false
        }
        if lhs.endToEndId != rhs.endToEndId {
            return false
        }
        if lhs.mandateId != rhs.mandateId {
            return false
        }
        if lhs.creditorId != rhs.creditorId {
            return false
        }
        if lhs.amount != rhs.amount {
            return false
        }
        if lhs.reversal != rhs.reversal {
            return false
        }
        if lhs.originalAmount != rhs.originalAmount {
            return false
        }
        if lhs.exchanges != rhs.exchanges {
            return false
        }
        if lhs.fees != rhs.fees {
            return false
        }
        if lhs.creditor != rhs.creditor {
            return false
        }
        if lhs.debtor != rhs.debtor {
            return false
        }
        if lhs.remittanceInformation != rhs.remittanceInformation {
            return false
        }
        if lhs.purposeCode != rhs.purposeCode {
            return false
        }
        if lhs.bankTransactionCodes != rhs.bankTransactionCodes {
            return false
        }
        if lhs.additionalInformation != rhs.additionalInformation {
            return false
        }
        return true
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(accountServicerReference)
        hasher.combine(paymentId)
        hasher.combine(transactionId)
        hasher.combine(endToEndId)
        hasher.combine(mandateId)
        hasher.combine(creditorId)
        hasher.combine(amount)
        hasher.combine(reversal)
        hasher.combine(originalAmount)
        hasher.combine(exchanges)
        hasher.combine(fees)
        hasher.combine(creditor)
        hasher.combine(debtor)
        hasher.combine(remittanceInformation)
        hasher.combine(purposeCode)
        hasher.combine(bankTransactionCodes)
        hasher.combine(additionalInformation)
    }
}



#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeBatchTransactionDetails: FfiConverterRustBuffer {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> BatchTransactionDetails {
        return
            try BatchTransactionDetails(
                accountServicerReference: FfiConverterOptionString.read(from: &buf), 
                paymentId: FfiConverterOptionString.read(from: &buf), 
                transactionId: FfiConverterOptionString.read(from: &buf), 
                endToEndId: FfiConverterOptionString.read(from: &buf), 
                mandateId: FfiConverterOptionString.read(from: &buf), 
                creditorId: FfiConverterOptionString.read(from: &buf), 
                amount: FfiConverterOptionTypeAmount.read(from: &buf), 
                reversal: FfiConverterBool.read(from: &buf), 
                originalAmount: FfiConverterOptionTypeAmount.read(from: &buf), 
                exchanges: FfiConverterSequenceTypeExchangeRate.read(from: &buf), 
                fees: FfiConverterSequenceTypeFee.read(from: &buf), 
                creditor: FfiConverterOptionTypeParty.read(from: &buf), 
                debtor: FfiConverterOptionTypeParty.read(from: &buf), 
                remittanceInformation: FfiConverterSequenceString.read(from: &buf), 
                purposeCode: FfiConverterOptionString.read(from: &buf), 
                bankTransactionCodes: FfiConverterSequenceTypeBankTransactionCode.read(from: &buf), 
                additionalInformation: FfiConverterOptionString.read(from: &buf)
        )
    }

    public static func write(_ value: BatchTransactionDetails, into buf: inout [UInt8]) {
        FfiConverterOptionString.write(value.accountServicerReference, into: &buf)
        FfiConverterOptionString.write(value.paymentId, into: &buf)
        FfiConverterOptionString.write(value.transactionId, into: &buf)
        FfiConverterOptionString.write(value.endToEndId, into: &buf)
        FfiConverterOptionString.write(value.mandateId, into: &buf)
        FfiConverterOptionString.write(value.creditorId, into: &buf)
        FfiConverterOptionTypeAmount.write(value.amount, into: &buf)
        FfiConverterBool.write(value.reversal, into: &buf)
        FfiConverterOptionTypeAmount.write(value.originalAmount, into: &buf)
        FfiConverterSequenceTypeExchangeRate.write(value.exchanges, into: &buf)
        FfiConverterSequenceTypeFee.write(value.fees, into: &buf)
        FfiConverterOptionTypeParty.write(value.creditor, into: &buf)
        FfiConverterOptionTypeParty.write(value.debtor, into: &buf)
        FfiConverterSequenceString.write(value.remittanceInformation, into: &buf)
        FfiConverterOptionString.write(value.purposeCode, into: &buf)
        FfiConverterSequenceTypeBankTransactionCode.write(value.bankTransactionCodes, into: &buf)
        FfiConverterOptionString.write(value.additionalInformation, into: &buf)
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeBatchTransactionDetails_lift(_ buf: RustBuffer) throws -> BatchTransactionDetails {
    return try FfiConverterTypeBatchTransactionDetails.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeBatchTransactionDetails_lower(_ value: BatchTransactionDetails) -> RustBuffer {
    return FfiConverterTypeBatchTransactionDetails.lower(value)
}


public struct ConnectionInfo {
    public var id: ConnectionId
    public var displayName: String
    public var credentials: CredentialsModel
    public var userId: String?
    public var advice: String?
    public var logoId: String

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(id: ConnectionId, displayName: String, credentials: CredentialsModel, userId: String? = nil, advice: String? = nil, logoId: String) {
        self.id = id
        self.displayName = displayName
        self.credentials = credentials
        self.userId = userId
        self.advice = advice
        self.logoId = logoId
    }
}

#if compiler(>=6)
extension ConnectionInfo: Sendable {}
#endif


extension ConnectionInfo: Equatable, Hashable {
    public static func ==(lhs: ConnectionInfo, rhs: ConnectionInfo) -> Bool {
        if lhs.id != rhs.id {
            return false
        }
        if lhs.displayName != rhs.displayName {
            return false
        }
        if lhs.credentials != rhs.credentials {
            return false
        }
        if lhs.userId != rhs.userId {
            return false
        }
        if lhs.advice != rhs.advice {
            return false
        }
        if lhs.logoId != rhs.logoId {
            return false
        }
        return true
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
        hasher.combine(displayName)
        hasher.combine(credentials)
        hasher.combine(userId)
        hasher.combine(advice)
        hasher.combine(logoId)
    }
}



#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeConnectionInfo: FfiConverterRustBuffer {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> ConnectionInfo {
        return
            try ConnectionInfo(
                id: FfiConverterTypeConnectionId.read(from: &buf), 
                displayName: FfiConverterString.read(from: &buf), 
                credentials: FfiConverterTypeCredentialsModel.read(from: &buf), 
                userId: FfiConverterOptionString.read(from: &buf), 
                advice: FfiConverterOptionString.read(from: &buf), 
                logoId: FfiConverterString.read(from: &buf)
        )
    }

    public static func write(_ value: ConnectionInfo, into buf: inout [UInt8]) {
        FfiConverterTypeConnectionId.write(value.id, into: &buf)
        FfiConverterString.write(value.displayName, into: &buf)
        FfiConverterTypeCredentialsModel.write(value.credentials, into: &buf)
        FfiConverterOptionString.write(value.userId, into: &buf)
        FfiConverterOptionString.write(value.advice, into: &buf)
        FfiConverterString.write(value.logoId, into: &buf)
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeConnectionInfo_lift(_ buf: RustBuffer) throws -> ConnectionInfo {
    return try FfiConverterTypeConnectionInfo.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeConnectionInfo_lower(_ value: ConnectionInfo) -> RustBuffer {
    return FfiConverterTypeConnectionInfo.lower(value)
}


public struct Credentials {
    public var connectionId: ConnectionId
    public var userId: String?
    public var password: String?
    public var connectionData: ConnectionData?

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(connectionId: ConnectionId, userId: String? = nil, password: String? = nil, connectionData: ConnectionData? = nil) {
        self.connectionId = connectionId
        self.userId = userId
        self.password = password
        self.connectionData = connectionData
    }
}

#if compiler(>=6)
extension Credentials: Sendable {}
#endif


extension Credentials: Equatable, Hashable {
    public static func ==(lhs: Credentials, rhs: Credentials) -> Bool {
        if lhs.connectionId != rhs.connectionId {
            return false
        }
        if lhs.userId != rhs.userId {
            return false
        }
        if lhs.password != rhs.password {
            return false
        }
        if lhs.connectionData != rhs.connectionData {
            return false
        }
        return true
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(connectionId)
        hasher.combine(userId)
        hasher.combine(password)
        hasher.combine(connectionData)
    }
}



#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeCredentials: FfiConverterRustBuffer {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> Credentials {
        return
            try Credentials(
                connectionId: FfiConverterTypeConnectionId.read(from: &buf), 
                userId: FfiConverterOptionString.read(from: &buf), 
                password: FfiConverterOptionString.read(from: &buf), 
                connectionData: FfiConverterOptionTypeConnectionData.read(from: &buf)
        )
    }

    public static func write(_ value: Credentials, into buf: inout [UInt8]) {
        FfiConverterTypeConnectionId.write(value.connectionId, into: &buf)
        FfiConverterOptionString.write(value.userId, into: &buf)
        FfiConverterOptionString.write(value.password, into: &buf)
        FfiConverterOptionTypeConnectionData.write(value.connectionData, into: &buf)
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeCredentials_lift(_ buf: RustBuffer) throws -> Credentials {
    return try FfiConverterTypeCredentials.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeCredentials_lower(_ value: Credentials) -> RustBuffer {
    return FfiConverterTypeCredentials.lower(value)
}


public struct ExchangeRate {
    /**
     * ISO 4217 Alpha 3 currency code of the source currency that gets converted.
     */
    public var sourceCurrency: String
    /**
     * ISO 4217 Alpha 3 currency code of the target currency that
     * the source currency gets converted into.
     */
    public var targetCurrency: String?
    /**
     * ISO 4217 Alpha 3 currency code of the unit currency for the exchange rate.
     */
    public var unitCurrency: String?
    public var exchangeRate: Decimal

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(
        /**
         * ISO 4217 Alpha 3 currency code of the source currency that gets converted.
         */sourceCurrency: String, 
        /**
         * ISO 4217 Alpha 3 currency code of the target currency that
         * the source currency gets converted into.
         */targetCurrency: String? = nil, 
        /**
         * ISO 4217 Alpha 3 currency code of the unit currency for the exchange rate.
         */unitCurrency: String? = nil, exchangeRate: Decimal) {
        self.sourceCurrency = sourceCurrency
        self.targetCurrency = targetCurrency
        self.unitCurrency = unitCurrency
        self.exchangeRate = exchangeRate
    }
}

#if compiler(>=6)
extension ExchangeRate: Sendable {}
#endif


extension ExchangeRate: Equatable, Hashable {
    public static func ==(lhs: ExchangeRate, rhs: ExchangeRate) -> Bool {
        if lhs.sourceCurrency != rhs.sourceCurrency {
            return false
        }
        if lhs.targetCurrency != rhs.targetCurrency {
            return false
        }
        if lhs.unitCurrency != rhs.unitCurrency {
            return false
        }
        if lhs.exchangeRate != rhs.exchangeRate {
            return false
        }
        return true
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(sourceCurrency)
        hasher.combine(targetCurrency)
        hasher.combine(unitCurrency)
        hasher.combine(exchangeRate)
    }
}



#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeExchangeRate: FfiConverterRustBuffer {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> ExchangeRate {
        return
            try ExchangeRate(
                sourceCurrency: FfiConverterString.read(from: &buf), 
                targetCurrency: FfiConverterOptionString.read(from: &buf), 
                unitCurrency: FfiConverterOptionString.read(from: &buf), 
                exchangeRate: FfiConverterTypeDecimal.read(from: &buf)
        )
    }

    public static func write(_ value: ExchangeRate, into buf: inout [UInt8]) {
        FfiConverterString.write(value.sourceCurrency, into: &buf)
        FfiConverterOptionString.write(value.targetCurrency, into: &buf)
        FfiConverterOptionString.write(value.unitCurrency, into: &buf)
        FfiConverterTypeDecimal.write(value.exchangeRate, into: &buf)
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeExchangeRate_lift(_ buf: RustBuffer) throws -> ExchangeRate {
    return try FfiConverterTypeExchangeRate.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeExchangeRate_lower(_ value: ExchangeRate) -> RustBuffer {
    return FfiConverterTypeExchangeRate.lower(value)
}


public struct Party {
    /**
     * Creditor / debtor name.
     */
    public var name: String?
    /**
     * ISO 20022 IBAN2007Identifier for the creditor / debtor account.
     */
    public var iban: String?
    /**
     * ISO 20022 BICFIIdentifier for the creditor / debtor agent.
     */
    public var bic: String?
    /**
     * Ultimate creditor / debtor (name).
     */
    public var ultimate: String?

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(
        /**
         * Creditor / debtor name.
         */name: String? = nil, 
        /**
         * ISO 20022 IBAN2007Identifier for the creditor / debtor account.
         */iban: String? = nil, 
        /**
         * ISO 20022 BICFIIdentifier for the creditor / debtor agent.
         */bic: String? = nil, 
        /**
         * Ultimate creditor / debtor (name).
         */ultimate: String? = nil) {
        self.name = name
        self.iban = iban
        self.bic = bic
        self.ultimate = ultimate
    }
}

#if compiler(>=6)
extension Party: Sendable {}
#endif


extension Party: Equatable, Hashable {
    public static func ==(lhs: Party, rhs: Party) -> Bool {
        if lhs.name != rhs.name {
            return false
        }
        if lhs.iban != rhs.iban {
            return false
        }
        if lhs.bic != rhs.bic {
            return false
        }
        if lhs.ultimate != rhs.ultimate {
            return false
        }
        return true
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(name)
        hasher.combine(iban)
        hasher.combine(bic)
        hasher.combine(ultimate)
    }
}



#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeParty: FfiConverterRustBuffer {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> Party {
        return
            try Party(
                name: FfiConverterOptionString.read(from: &buf), 
                iban: FfiConverterOptionString.read(from: &buf), 
                bic: FfiConverterOptionString.read(from: &buf), 
                ultimate: FfiConverterOptionString.read(from: &buf)
        )
    }

    public static func write(_ value: Party, into buf: inout [UInt8]) {
        FfiConverterOptionString.write(value.name, into: &buf)
        FfiConverterOptionString.write(value.iban, into: &buf)
        FfiConverterOptionString.write(value.bic, into: &buf)
        FfiConverterOptionString.write(value.ultimate, into: &buf)
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeParty_lift(_ buf: RustBuffer) throws -> Party {
    return try FfiConverterTypeParty.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeParty_lower(_ value: Party) -> RustBuffer {
    return FfiConverterTypeParty.lower(value)
}


public struct PaymentInitiation {

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init() {
    }
}

#if compiler(>=6)
extension PaymentInitiation: Sendable {}
#endif


extension PaymentInitiation: Equatable, Hashable {
    public static func ==(lhs: PaymentInitiation, rhs: PaymentInitiation) -> Bool {
        return true
    }

    public func hash(into hasher: inout Hasher) {
    }
}



#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypePaymentInitiation: FfiConverterRustBuffer {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> PaymentInitiation {
        return
            PaymentInitiation()
    }

    public static func write(_ value: PaymentInitiation, into buf: inout [UInt8]) {
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypePaymentInitiation_lift(_ buf: RustBuffer) throws -> PaymentInitiation {
    return try FfiConverterTypePaymentInitiation.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypePaymentInitiation_lower(_ value: PaymentInitiation) -> RustBuffer {
    return FfiConverterTypePaymentInitiation.lower(value)
}


public struct Transaction {
    /**
     * Identifier used for delta requests.
     */
    public var entryReference: String?
    public var batch: BatchData?
    /**
     * Booking date (ASPSP's books).
     */
    public var bookingDate: NaiveDate?
    /**
     * Value date. Expected / requested value date in case of pending entries.
     */
    public var valueDate: NaiveDate?
    /**
     * Date of the actual transaction, e.g. a card payment.
     */
    public var transactionDate: NaiveDate?
    /**
     * Transaction status.
     */
    public var status: TransactionStatus
    /**
     * Unique reference assigned by the account servicer.
     */
    public var accountServicerReference: String?
    /**
     * Unique identifier assigned by the sending party.
     */
    public var paymentId: String?
    /**
     * Unique identifier assigned by the first instructing agent.
     */
    public var transactionId: String?
    /**
     * Unique end-to-end identifier assigned by the initiating party.
     */
    public var endToEndId: String?
    /**
     * Mandate identifier.
     */
    public var mandateId: String?
    /**
     * SEPA creditor identifier.
     */
    public var creditorId: String?
    /**
     * Transaction amount as billed to the account.
     */
    public var amount: Amount
    /**
     * Indicator for reversals.
     */
    public var reversal: Bool
    /**
     * Original amount of the transaction.
     */
    public var originalAmount: Amount?
    /**
     * Exchange rates.
     */
    public var exchanges: [ExchangeRate]
    /**
     * Any fees related to the transaction.
     */
    public var fees: [Fee]
    /**
     * Creditor data. In case of reversals this refers to the initial transaction.
     */
    public var creditor: Party?
    /**
     * Debtor data. In case of reversals this refers to the initial transaction.
     */
    public var debtor: Party?
    /**
     * Remittance (purpose).
     */
    public var remittanceInformation: [String]
    /**
     * ISO 20022 ExternalPurpose1Code.
     */
    public var purposeCode: String?
    /**
     * Bank Transaction Codes.
     */
    public var bankTransactionCodes: [BankTransactionCode]
    /**
     * Additional information attached to the transaction.
     *
     * This might be a proprietary, localized, human-readable long text corresponding to some machine-readable bank transaction code that is not directly provided by the bank.
     */
    public var additionalInformation: String?

    // Default memberwise initializers are never public by default, so we
    // declare one manually.
    public init(
        /**
         * Identifier used for delta requests.
         */entryReference: String? = nil, batch: BatchData? = nil, 
        /**
         * Booking date (ASPSP's books).
         */bookingDate: NaiveDate? = nil, 
        /**
         * Value date. Expected / requested value date in case of pending entries.
         */valueDate: NaiveDate? = nil, 
        /**
         * Date of the actual transaction, e.g. a card payment.
         */transactionDate: NaiveDate? = nil, 
        /**
         * Transaction status.
         */status: TransactionStatus, 
        /**
         * Unique reference assigned by the account servicer.
         */accountServicerReference: String? = nil, 
        /**
         * Unique identifier assigned by the sending party.
         */paymentId: String? = nil, 
        /**
         * Unique identifier assigned by the first instructing agent.
         */transactionId: String? = nil, 
        /**
         * Unique end-to-end identifier assigned by the initiating party.
         */endToEndId: String? = nil, 
        /**
         * Mandate identifier.
         */mandateId: String? = nil, 
        /**
         * SEPA creditor identifier.
         */creditorId: String? = nil, 
        /**
         * Transaction amount as billed to the account.
         */amount: Amount, 
        /**
         * Indicator for reversals.
         */reversal: Bool = false, 
        /**
         * Original amount of the transaction.
         */originalAmount: Amount? = nil, 
        /**
         * Exchange rates.
         */exchanges: [ExchangeRate] = [], 
        /**
         * Any fees related to the transaction.
         */fees: [Fee] = [], 
        /**
         * Creditor data. In case of reversals this refers to the initial transaction.
         */creditor: Party? = nil, 
        /**
         * Debtor data. In case of reversals this refers to the initial transaction.
         */debtor: Party? = nil, 
        /**
         * Remittance (purpose).
         */remittanceInformation: [String] = [], 
        /**
         * ISO 20022 ExternalPurpose1Code.
         */purposeCode: String? = nil, 
        /**
         * Bank Transaction Codes.
         */bankTransactionCodes: [BankTransactionCode] = [], 
        /**
         * Additional information attached to the transaction.
         *
         * This might be a proprietary, localized, human-readable long text corresponding to some machine-readable bank transaction code that is not directly provided by the bank.
         */additionalInformation: String? = nil) {
        self.entryReference = entryReference
        self.batch = batch
        self.bookingDate = bookingDate
        self.valueDate = valueDate
        self.transactionDate = transactionDate
        self.status = status
        self.accountServicerReference = accountServicerReference
        self.paymentId = paymentId
        self.transactionId = transactionId
        self.endToEndId = endToEndId
        self.mandateId = mandateId
        self.creditorId = creditorId
        self.amount = amount
        self.reversal = reversal
        self.originalAmount = originalAmount
        self.exchanges = exchanges
        self.fees = fees
        self.creditor = creditor
        self.debtor = debtor
        self.remittanceInformation = remittanceInformation
        self.purposeCode = purposeCode
        self.bankTransactionCodes = bankTransactionCodes
        self.additionalInformation = additionalInformation
    }
}

#if compiler(>=6)
extension Transaction: Sendable {}
#endif


extension Transaction: Equatable, Hashable {
    public static func ==(lhs: Transaction, rhs: Transaction) -> Bool {
        if lhs.entryReference != rhs.entryReference {
            return false
        }
        if lhs.batch != rhs.batch {
            return false
        }
        if lhs.bookingDate != rhs.bookingDate {
            return false
        }
        if lhs.valueDate != rhs.valueDate {
            return false
        }
        if lhs.transactionDate != rhs.transactionDate {
            return false
        }
        if lhs.status != rhs.status {
            return false
        }
        if lhs.accountServicerReference != rhs.accountServicerReference {
            return false
        }
        if lhs.paymentId != rhs.paymentId {
            return false
        }
        if lhs.transactionId != rhs.transactionId {
            return false
        }
        if lhs.endToEndId != rhs.endToEndId {
            return false
        }
        if lhs.mandateId != rhs.mandateId {
            return false
        }
        if lhs.creditorId != rhs.creditorId {
            return false
        }
        if lhs.amount != rhs.amount {
            return false
        }
        if lhs.reversal != rhs.reversal {
            return false
        }
        if lhs.originalAmount != rhs.originalAmount {
            return false
        }
        if lhs.exchanges != rhs.exchanges {
            return false
        }
        if lhs.fees != rhs.fees {
            return false
        }
        if lhs.creditor != rhs.creditor {
            return false
        }
        if lhs.debtor != rhs.debtor {
            return false
        }
        if lhs.remittanceInformation != rhs.remittanceInformation {
            return false
        }
        if lhs.purposeCode != rhs.purposeCode {
            return false
        }
        if lhs.bankTransactionCodes != rhs.bankTransactionCodes {
            return false
        }
        if lhs.additionalInformation != rhs.additionalInformation {
            return false
        }
        return true
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(entryReference)
        hasher.combine(batch)
        hasher.combine(bookingDate)
        hasher.combine(valueDate)
        hasher.combine(transactionDate)
        hasher.combine(status)
        hasher.combine(accountServicerReference)
        hasher.combine(paymentId)
        hasher.combine(transactionId)
        hasher.combine(endToEndId)
        hasher.combine(mandateId)
        hasher.combine(creditorId)
        hasher.combine(amount)
        hasher.combine(reversal)
        hasher.combine(originalAmount)
        hasher.combine(exchanges)
        hasher.combine(fees)
        hasher.combine(creditor)
        hasher.combine(debtor)
        hasher.combine(remittanceInformation)
        hasher.combine(purposeCode)
        hasher.combine(bankTransactionCodes)
        hasher.combine(additionalInformation)
    }
}



#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeTransaction: FfiConverterRustBuffer {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> Transaction {
        return
            try Transaction(
                entryReference: FfiConverterOptionString.read(from: &buf), 
                batch: FfiConverterOptionTypeBatchData.read(from: &buf), 
                bookingDate: FfiConverterOptionTypeNaiveDate.read(from: &buf), 
                valueDate: FfiConverterOptionTypeNaiveDate.read(from: &buf), 
                transactionDate: FfiConverterOptionTypeNaiveDate.read(from: &buf), 
                status: FfiConverterTypeTransactionStatus.read(from: &buf), 
                accountServicerReference: FfiConverterOptionString.read(from: &buf), 
                paymentId: FfiConverterOptionString.read(from: &buf), 
                transactionId: FfiConverterOptionString.read(from: &buf), 
                endToEndId: FfiConverterOptionString.read(from: &buf), 
                mandateId: FfiConverterOptionString.read(from: &buf), 
                creditorId: FfiConverterOptionString.read(from: &buf), 
                amount: FfiConverterTypeAmount.read(from: &buf), 
                reversal: FfiConverterBool.read(from: &buf), 
                originalAmount: FfiConverterOptionTypeAmount.read(from: &buf), 
                exchanges: FfiConverterSequenceTypeExchangeRate.read(from: &buf), 
                fees: FfiConverterSequenceTypeFee.read(from: &buf), 
                creditor: FfiConverterOptionTypeParty.read(from: &buf), 
                debtor: FfiConverterOptionTypeParty.read(from: &buf), 
                remittanceInformation: FfiConverterSequenceString.read(from: &buf), 
                purposeCode: FfiConverterOptionString.read(from: &buf), 
                bankTransactionCodes: FfiConverterSequenceTypeBankTransactionCode.read(from: &buf), 
                additionalInformation: FfiConverterOptionString.read(from: &buf)
        )
    }

    public static func write(_ value: Transaction, into buf: inout [UInt8]) {
        FfiConverterOptionString.write(value.entryReference, into: &buf)
        FfiConverterOptionTypeBatchData.write(value.batch, into: &buf)
        FfiConverterOptionTypeNaiveDate.write(value.bookingDate, into: &buf)
        FfiConverterOptionTypeNaiveDate.write(value.valueDate, into: &buf)
        FfiConverterOptionTypeNaiveDate.write(value.transactionDate, into: &buf)
        FfiConverterTypeTransactionStatus.write(value.status, into: &buf)
        FfiConverterOptionString.write(value.accountServicerReference, into: &buf)
        FfiConverterOptionString.write(value.paymentId, into: &buf)
        FfiConverterOptionString.write(value.transactionId, into: &buf)
        FfiConverterOptionString.write(value.endToEndId, into: &buf)
        FfiConverterOptionString.write(value.mandateId, into: &buf)
        FfiConverterOptionString.write(value.creditorId, into: &buf)
        FfiConverterTypeAmount.write(value.amount, into: &buf)
        FfiConverterBool.write(value.reversal, into: &buf)
        FfiConverterOptionTypeAmount.write(value.originalAmount, into: &buf)
        FfiConverterSequenceTypeExchangeRate.write(value.exchanges, into: &buf)
        FfiConverterSequenceTypeFee.write(value.fees, into: &buf)
        FfiConverterOptionTypeParty.write(value.creditor, into: &buf)
        FfiConverterOptionTypeParty.write(value.debtor, into: &buf)
        FfiConverterSequenceString.write(value.remittanceInformation, into: &buf)
        FfiConverterOptionString.write(value.purposeCode, into: &buf)
        FfiConverterSequenceTypeBankTransactionCode.write(value.bankTransactionCodes, into: &buf)
        FfiConverterOptionString.write(value.additionalInformation, into: &buf)
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeTransaction_lift(_ buf: RustBuffer) throws -> Transaction {
    return try FfiConverterTypeTransaction.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeTransaction_lower(_ value: Transaction) -> RustBuffer {
    return FfiConverterTypeTransaction.lower(value)
}

// Note that we don't yet support `indirect` for enums.
// See https://github.com/mozilla/uniffi-rs/issues/396 for further discussion.

public enum AccountField {
    
    case iban
    case number
    case bic
    case bankCode
    case currency
    case name
    case displayName
    case ownerName
    case productName
    case status
    case type
}


#if compiler(>=6)
extension AccountField: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeAccountField: FfiConverterRustBuffer {
    typealias SwiftType = AccountField

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> AccountField {
        let variant: Int32 = try readInt(&buf)
        switch variant {
        
        case 1: return .iban
        
        case 2: return .number
        
        case 3: return .bic
        
        case 4: return .bankCode
        
        case 5: return .currency
        
        case 6: return .name
        
        case 7: return .displayName
        
        case 8: return .ownerName
        
        case 9: return .productName
        
        case 10: return .status
        
        case 11: return .type
        
        default: throw UniffiInternalError.unexpectedEnumCase
        }
    }

    public static func write(_ value: AccountField, into buf: inout [UInt8]) {
        switch value {
        
        
        case .iban:
            writeInt(&buf, Int32(1))
        
        
        case .number:
            writeInt(&buf, Int32(2))
        
        
        case .bic:
            writeInt(&buf, Int32(3))
        
        
        case .bankCode:
            writeInt(&buf, Int32(4))
        
        
        case .currency:
            writeInt(&buf, Int32(5))
        
        
        case .name:
            writeInt(&buf, Int32(6))
        
        
        case .displayName:
            writeInt(&buf, Int32(7))
        
        
        case .ownerName:
            writeInt(&buf, Int32(8))
        
        
        case .productName:
            writeInt(&buf, Int32(9))
        
        
        case .status:
            writeInt(&buf, Int32(10))
        
        
        case .type:
            writeInt(&buf, Int32(11))
        
        }
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAccountField_lift(_ buf: RustBuffer) throws -> AccountField {
    return try FfiConverterTypeAccountField.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAccountField_lower(_ value: AccountField) -> RustBuffer {
    return FfiConverterTypeAccountField.lower(value)
}


extension AccountField: Equatable, Hashable {}



// Note that we don't yet support `indirect` for enums.
// See https://github.com/mozilla/uniffi-rs/issues/396 for further discussion.

public enum AccountIdentifier {
    
    /**
     * ISO 20022 IBAN2007Identifier.
     */
    case iban(String
    )
}


#if compiler(>=6)
extension AccountIdentifier: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeAccountIdentifier: FfiConverterRustBuffer {
    typealias SwiftType = AccountIdentifier

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> AccountIdentifier {
        let variant: Int32 = try readInt(&buf)
        switch variant {
        
        case 1: return .iban(try FfiConverterString.read(from: &buf)
        )
        
        default: throw UniffiInternalError.unexpectedEnumCase
        }
    }

    public static func write(_ value: AccountIdentifier, into buf: inout [UInt8]) {
        switch value {
        
        
        case let .iban(v1):
            writeInt(&buf, Int32(1))
            FfiConverterString.write(v1, into: &buf)
            
        }
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAccountIdentifier_lift(_ buf: RustBuffer) throws -> AccountIdentifier {
    return try FfiConverterTypeAccountIdentifier.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeAccountIdentifier_lower(_ value: AccountIdentifier) -> RustBuffer {
    return FfiConverterTypeAccountIdentifier.lower(value)
}


extension AccountIdentifier: Equatable, Hashable {}



// Note that we don't yet support `indirect` for enums.
// See https://github.com/mozilla/uniffi-rs/issues/396 for further discussion.

public enum BankTransactionCode {
    
    /**
     * ISO 20022 Bank Transaction Code.
     */
    case iso(
        /**
         * ISO 20022 ExternalBankTransactionDomain1Code.
         */domain: String, 
        /**
         * ISO 20022 ExternalBankTransactionFamily1Code.
         */family: String, 
        /**
         * ISO 20022 ExternalBankTransactionSubFamily1Code.
         */subFamily: String
    )
    /**
     * SWIFT transaction code.
     */
    case swift(String
    )
    /**
     * BAI2 transaction code.
     */
    case bai(String
    )
    /**
     * National transaction code, e.g. German GVC.
     */
    case national(code: String, country: CountryCode
    )
    /**
     * Unspecified transaction codes, possibly with an issuer information.
     */
    case other(code: String, issuer: String?
    )
}


#if compiler(>=6)
extension BankTransactionCode: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeBankTransactionCode: FfiConverterRustBuffer {
    typealias SwiftType = BankTransactionCode

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> BankTransactionCode {
        let variant: Int32 = try readInt(&buf)
        switch variant {
        
        case 1: return .iso(domain: try FfiConverterString.read(from: &buf), family: try FfiConverterString.read(from: &buf), subFamily: try FfiConverterString.read(from: &buf)
        )
        
        case 2: return .swift(try FfiConverterString.read(from: &buf)
        )
        
        case 3: return .bai(try FfiConverterString.read(from: &buf)
        )
        
        case 4: return .national(code: try FfiConverterString.read(from: &buf), country: try FfiConverterTypeCountryCode.read(from: &buf)
        )
        
        case 5: return .other(code: try FfiConverterString.read(from: &buf), issuer: try FfiConverterOptionString.read(from: &buf)
        )
        
        default: throw UniffiInternalError.unexpectedEnumCase
        }
    }

    public static func write(_ value: BankTransactionCode, into buf: inout [UInt8]) {
        switch value {
        
        
        case let .iso(domain,family,subFamily):
            writeInt(&buf, Int32(1))
            FfiConverterString.write(domain, into: &buf)
            FfiConverterString.write(family, into: &buf)
            FfiConverterString.write(subFamily, into: &buf)
            
        
        case let .swift(v1):
            writeInt(&buf, Int32(2))
            FfiConverterString.write(v1, into: &buf)
            
        
        case let .bai(v1):
            writeInt(&buf, Int32(3))
            FfiConverterString.write(v1, into: &buf)
            
        
        case let .national(code,country):
            writeInt(&buf, Int32(4))
            FfiConverterString.write(code, into: &buf)
            FfiConverterTypeCountryCode.write(country, into: &buf)
            
        
        case let .other(code,issuer):
            writeInt(&buf, Int32(5))
            FfiConverterString.write(code, into: &buf)
            FfiConverterOptionString.write(issuer, into: &buf)
            
        }
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeBankTransactionCode_lift(_ buf: RustBuffer) throws -> BankTransactionCode {
    return try FfiConverterTypeBankTransactionCode.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeBankTransactionCode_lower(_ value: BankTransactionCode) -> RustBuffer {
    return FfiConverterTypeBankTransactionCode.lower(value)
}


extension BankTransactionCode: Equatable, Hashable {}



// Note that we don't yet support `indirect` for enums.
// See https://github.com/mozilla/uniffi-rs/issues/396 for further discussion.
/**
 * Type of connections to consider when searching
 */

public enum ConnectionType {
    
    /**
     * Production connections.
     */
    case production
    /**
     * Sandboxes connections, especially test systems provided by third-parties.
     */
    case sandboxes
}


#if compiler(>=6)
extension ConnectionType: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeConnectionType: FfiConverterRustBuffer {
    typealias SwiftType = ConnectionType

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> ConnectionType {
        let variant: Int32 = try readInt(&buf)
        switch variant {
        
        case 1: return .production
        
        case 2: return .sandboxes
        
        default: throw UniffiInternalError.unexpectedEnumCase
        }
    }

    public static func write(_ value: ConnectionType, into buf: inout [UInt8]) {
        switch value {
        
        
        case .production:
            writeInt(&buf, Int32(1))
        
        
        case .sandboxes:
            writeInt(&buf, Int32(2))
        
        }
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeConnectionType_lift(_ buf: RustBuffer) throws -> ConnectionType {
    return try FfiConverterTypeConnectionType.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeConnectionType_lower(_ value: ConnectionType) -> RustBuffer {
    return FfiConverterTypeConnectionType.lower(value)
}


extension ConnectionType: Equatable, Hashable {}



// Note that we don't yet support `indirect` for enums.
// See https://github.com/mozilla/uniffi-rs/issues/396 for further discussion.

public enum SupportedService {
    
    case collectPayment
}


#if compiler(>=6)
extension SupportedService: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeSupportedService: FfiConverterRustBuffer {
    typealias SwiftType = SupportedService

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> SupportedService {
        let variant: Int32 = try readInt(&buf)
        switch variant {
        
        case 1: return .collectPayment
        
        default: throw UniffiInternalError.unexpectedEnumCase
        }
    }

    public static func write(_ value: SupportedService, into buf: inout [UInt8]) {
        switch value {
        
        
        case .collectPayment:
            writeInt(&buf, Int32(1))
        
        }
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeSupportedService_lift(_ buf: RustBuffer) throws -> SupportedService {
    return try FfiConverterTypeSupportedService.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeSupportedService_lower(_ value: SupportedService) -> RustBuffer {
    return FfiConverterTypeSupportedService.lower(value)
}


extension SupportedService: Equatable, Hashable {}



// Note that we don't yet support `indirect` for enums.
// See https://github.com/mozilla/uniffi-rs/issues/396 for further discussion.

public enum TicketErrorCode {
    
    /**
     * Missing "yaxi-ticket" header
     */
    case missing
    /**
     * Invalid ticket
     */
    case invalid
    /**
     * Ticket token lacks "kid"
     */
    case missingKey
    /**
     * Unknown key
     */
    case unknownKey
    /**
     * Ticket does not match service
     */
    case mismatch
    /**
     * Ticket is expired
     */
    case expired
    /**
     * Ticket lifetime is too long
     */
    case invalidLifetime
}


#if compiler(>=6)
extension TicketErrorCode: Sendable {}
#endif

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeTicketErrorCode: FfiConverterRustBuffer {
    typealias SwiftType = TicketErrorCode

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> TicketErrorCode {
        let variant: Int32 = try readInt(&buf)
        switch variant {
        
        case 1: return .missing
        
        case 2: return .invalid
        
        case 3: return .missingKey
        
        case 4: return .unknownKey
        
        case 5: return .mismatch
        
        case 6: return .expired
        
        case 7: return .invalidLifetime
        
        default: throw UniffiInternalError.unexpectedEnumCase
        }
    }

    public static func write(_ value: TicketErrorCode, into buf: inout [UInt8]) {
        switch value {
        
        
        case .missing:
            writeInt(&buf, Int32(1))
        
        
        case .invalid:
            writeInt(&buf, Int32(2))
        
        
        case .missingKey:
            writeInt(&buf, Int32(3))
        
        
        case .unknownKey:
            writeInt(&buf, Int32(4))
        
        
        case .mismatch:
            writeInt(&buf, Int32(5))
        
        
        case .expired:
            writeInt(&buf, Int32(6))
        
        
        case .invalidLifetime:
            writeInt(&buf, Int32(7))
        
        }
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeTicketErrorCode_lift(_ buf: RustBuffer) throws -> TicketErrorCode {
    return try FfiConverterTypeTicketErrorCode.lift(buf)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeTicketErrorCode_lower(_ value: TicketErrorCode) -> RustBuffer {
    return FfiConverterTypeTicketErrorCode.lower(value)
}


extension TicketErrorCode: Equatable, Hashable {}



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
fileprivate struct FfiConverterOptionTypeAmount: FfiConverterRustBuffer {
    typealias SwiftType = Amount?

    public static func write(_ value: SwiftType, into buf: inout [UInt8]) {
        guard let value = value else {
            writeInt(&buf, Int8(0))
            return
        }
        writeInt(&buf, Int8(1))
        FfiConverterTypeAmount.write(value, into: &buf)
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> SwiftType {
        switch try readInt(&buf) as Int8 {
        case 0: return nil
        case 1: return try FfiConverterTypeAmount.read(from: &buf)
        default: throw UniffiInternalError.unexpectedOptionalTag
        }
    }
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterOptionTypeBatchData: FfiConverterRustBuffer {
    typealias SwiftType = BatchData?

    public static func write(_ value: SwiftType, into buf: inout [UInt8]) {
        guard let value = value else {
            writeInt(&buf, Int8(0))
            return
        }
        writeInt(&buf, Int8(1))
        FfiConverterTypeBatchData.write(value, into: &buf)
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> SwiftType {
        switch try readInt(&buf) as Int8 {
        case 0: return nil
        case 1: return try FfiConverterTypeBatchData.read(from: &buf)
        default: throw UniffiInternalError.unexpectedOptionalTag
        }
    }
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterOptionTypeParty: FfiConverterRustBuffer {
    typealias SwiftType = Party?

    public static func write(_ value: SwiftType, into buf: inout [UInt8]) {
        guard let value = value else {
            writeInt(&buf, Int8(0))
            return
        }
        writeInt(&buf, Int8(1))
        FfiConverterTypeParty.write(value, into: &buf)
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> SwiftType {
        switch try readInt(&buf) as Int8 {
        case 0: return nil
        case 1: return try FfiConverterTypeParty.read(from: &buf)
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
fileprivate struct FfiConverterOptionTypeNaiveDate: FfiConverterRustBuffer {
    typealias SwiftType = NaiveDate?

    public static func write(_ value: SwiftType, into buf: inout [UInt8]) {
        guard let value = value else {
            writeInt(&buf, Int8(0))
            return
        }
        writeInt(&buf, Int8(1))
        FfiConverterTypeNaiveDate.write(value, into: &buf)
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> SwiftType {
        switch try readInt(&buf) as Int8 {
        case 0: return nil
        case 1: return try FfiConverterTypeNaiveDate.read(from: &buf)
        default: throw UniffiInternalError.unexpectedOptionalTag
        }
    }
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterSequenceString: FfiConverterRustBuffer {
    typealias SwiftType = [String]

    public static func write(_ value: [String], into buf: inout [UInt8]) {
        let len = Int32(value.count)
        writeInt(&buf, len)
        for item in value {
            FfiConverterString.write(item, into: &buf)
        }
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> [String] {
        let len: Int32 = try readInt(&buf)
        var seq = [String]()
        seq.reserveCapacity(Int(len))
        for _ in 0 ..< len {
            seq.append(try FfiConverterString.read(from: &buf))
        }
        return seq
    }
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterSequenceTypeFee: FfiConverterRustBuffer {
    typealias SwiftType = [Fee]

    public static func write(_ value: [Fee], into buf: inout [UInt8]) {
        let len = Int32(value.count)
        writeInt(&buf, len)
        for item in value {
            FfiConverterTypeFee.write(item, into: &buf)
        }
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> [Fee] {
        let len: Int32 = try readInt(&buf)
        var seq = [Fee]()
        seq.reserveCapacity(Int(len))
        for _ in 0 ..< len {
            seq.append(try FfiConverterTypeFee.read(from: &buf))
        }
        return seq
    }
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterSequenceTypeBatchTransactionDetails: FfiConverterRustBuffer {
    typealias SwiftType = [BatchTransactionDetails]

    public static func write(_ value: [BatchTransactionDetails], into buf: inout [UInt8]) {
        let len = Int32(value.count)
        writeInt(&buf, len)
        for item in value {
            FfiConverterTypeBatchTransactionDetails.write(item, into: &buf)
        }
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> [BatchTransactionDetails] {
        let len: Int32 = try readInt(&buf)
        var seq = [BatchTransactionDetails]()
        seq.reserveCapacity(Int(len))
        for _ in 0 ..< len {
            seq.append(try FfiConverterTypeBatchTransactionDetails.read(from: &buf))
        }
        return seq
    }
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterSequenceTypeExchangeRate: FfiConverterRustBuffer {
    typealias SwiftType = [ExchangeRate]

    public static func write(_ value: [ExchangeRate], into buf: inout [UInt8]) {
        let len = Int32(value.count)
        writeInt(&buf, len)
        for item in value {
            FfiConverterTypeExchangeRate.write(item, into: &buf)
        }
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> [ExchangeRate] {
        let len: Int32 = try readInt(&buf)
        var seq = [ExchangeRate]()
        seq.reserveCapacity(Int(len))
        for _ in 0 ..< len {
            seq.append(try FfiConverterTypeExchangeRate.read(from: &buf))
        }
        return seq
    }
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
fileprivate struct FfiConverterSequenceTypeBankTransactionCode: FfiConverterRustBuffer {
    typealias SwiftType = [BankTransactionCode]

    public static func write(_ value: [BankTransactionCode], into buf: inout [UInt8]) {
        let len = Int32(value.count)
        writeInt(&buf, len)
        for item in value {
            FfiConverterTypeBankTransactionCode.write(item, into: &buf)
        }
    }

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> [BankTransactionCode] {
        let len: Int32 = try readInt(&buf)
        var seq = [BankTransactionCode]()
        seq.reserveCapacity(Int(len))
        for _ in 0 ..< len {
            seq.append(try FfiConverterTypeBankTransactionCode.read(from: &buf))
        }
        return seq
    }
}


/**
 * Typealias from the type name used in the UDL file to the builtin type.  This
 * is needed because the UDL type name is used in function/method signatures.
 */
public typealias ConnectionData = Data

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeConnectionData: FfiConverter {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> ConnectionData {
        return try FfiConverterData.read(from: &buf)
    }

    public static func write(_ value: ConnectionData, into buf: inout [UInt8]) {
        return FfiConverterData.write(value, into: &buf)
    }

    public static func lift(_ value: RustBuffer) throws -> ConnectionData {
        return try FfiConverterData.lift(value)
    }

    public static func lower(_ value: ConnectionData) -> RustBuffer {
        return FfiConverterData.lower(value)
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeConnectionData_lift(_ value: RustBuffer) throws -> ConnectionData {
    return try FfiConverterTypeConnectionData.lift(value)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeConnectionData_lower(_ value: ConnectionData) -> RustBuffer {
    return FfiConverterTypeConnectionData.lower(value)
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





/**
 * Typealias from the type name used in the UDL file to the custom type.  This
 * is needed because the UDL type name is used in function/method signatures.
 */
public typealias NaiveDate = Date

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeNaiveDate: FfiConverter {

    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> NaiveDate {
        let builtinValue = try FfiConverterString.read(from: &buf)
        return { let formatter = DateFormatter(); formatter.dateFormat = "yyyy-MM-dd"; return formatter.date(from: builtinValue)! }()
    }

    public static func write(_ value: NaiveDate, into buf: inout [UInt8]) {
        let builtinValue = { () -> String in let formatter = DateFormatter(); formatter.dateFormat = "yyyy-MM-dd"; return formatter.string(from: value) }()
        return FfiConverterString.write(builtinValue, into: &buf)
    }

    public static func lift(_ value: RustBuffer) throws -> NaiveDate {
        let builtinValue = try FfiConverterString.lift(value)
        return { let formatter = DateFormatter(); formatter.dateFormat = "yyyy-MM-dd"; return formatter.date(from: builtinValue)! }()
    }

    public static func lower(_ value: NaiveDate) -> RustBuffer {
        let builtinValue = { () -> String in let formatter = DateFormatter(); formatter.dateFormat = "yyyy-MM-dd"; return formatter.string(from: value) }()
        return FfiConverterString.lower(builtinValue)
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeNaiveDate_lift(_ value: RustBuffer) throws -> NaiveDate {
    return try FfiConverterTypeNaiveDate.lift(value)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeNaiveDate_lower(_ value: NaiveDate) -> RustBuffer {
    return FfiConverterTypeNaiveDate.lower(value)
}



/**
 * Typealias from the type name used in the UDL file to the builtin type.  This
 * is needed because the UDL type name is used in function/method signatures.
 */
public typealias Session = Data

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public struct FfiConverterTypeSession: FfiConverter {
    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> Session {
        return try FfiConverterData.read(from: &buf)
    }

    public static func write(_ value: Session, into buf: inout [UInt8]) {
        return FfiConverterData.write(value, into: &buf)
    }

    public static func lift(_ value: RustBuffer) throws -> Session {
        return try FfiConverterData.lift(value)
    }

    public static func lower(_ value: Session) -> RustBuffer {
        return FfiConverterData.lower(value)
    }
}


#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeSession_lift(_ value: RustBuffer) throws -> Session {
    return try FfiConverterTypeSession.lift(value)
}

#if swift(>=5.8)
@_documentation(visibility: private)
#endif
public func FfiConverterTypeSession_lower(_ value: Session) -> RustBuffer {
    return FfiConverterTypeSession.lower(value)
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
    let scaffolding_contract_version = ffi_routex_api_uniffi_contract_version()
    if bindings_contract_version != scaffolding_contract_version {
        return InitializationResult.contractVersionMismatch
    }

    uniffiEnsureKitxCoreInitialized()
    return InitializationResult.ok
}()

// Make the ensure init function public so that other modules which have external type references to
// our types can call it.
public func uniffiEnsureRoutexApiInitialized() {
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