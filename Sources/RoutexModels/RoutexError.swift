import Foundation

/// Service-level error returned by the routex backend.
///
/// See [Errors](https://docs.yaxi.tech/errors.html) for the contract.
/// `userMessage` payloads are end-user facing copy from the bank or
/// routex; UIs should display them verbatim where present (see
/// ``userMessage``).
public enum RoutexError: Error, Sendable, Equatable {
    /// An unexpected error occurred. Usually retriable; check
    /// `RoutexClient.traceID` for diagnostics.
    case unexpectedError(userMessage: String?)
    /// The user canceled the flow.
    case canceled
    /// The supplied ``Credentials`` are not valid.
    case invalidCredentials(userMessage: String?)
    /// The service is blocked for the user. ``ServiceBlockedCode`` says
    /// why.
    case serviceBlocked(code: ServiceBlockedCode?, userMessage: String?)
    /// The user is not authorized for the service.
    case unauthorized(userMessage: String?)
    /// The bank rejected the request for exceeding the consent's permitted
    /// access frequency. Most common on non-interactive refresh calls made
    /// without a user in session; pass a ``UserInSession`` to lift that
    /// limit.
    case accessExceeded(userMessage: String?)
    /// Requested period is outside what the bank exposes.
    case periodOutOfBounds(userMessage: String?)
    /// The selected ``PaymentProduct`` is not supported in this context.
    case unsupportedProduct(reason: UnsupportedProductReason?, userMessage: String?)
    /// The bank rejected the payment. ``PaymentErrorCode`` says why.
    case paymentFailed(code: PaymentErrorCode?, userMessage: String?)
    /// An input value did not validate. The string is a machine-readable
    /// hint about which field.
    case unexpectedValue(error: String)
    /// The ``RoutexTicket`` is malformed, missing, or rejected.
    /// ``TicketErrorCode`` says why.
    case ticketError(error: String, code: TicketErrorCode)
    /// Upstream bank returned an error. ``ProviderErrorCode`` says why.
    case providerError(code: ProviderErrorCode?, userMessage: String?)
    /// The service call requires user interaction to complete.
    ///
    /// Only calls that pass ``ConnectionData`` instead of ``Credentials``
    /// produce this; with credentials the service returns a ``Dialog`` or
    /// ``Redirect`` instead. Recover by running the user through a call
    /// with credentials and persisting the connection data it returns.
    case interruptError
    /// HTTP 404 with an empty body. Synthesized client-side; not directly
    /// representable on the wire.
    case notFound
    /// HTTP error response that does not carry a routex error, e.g. from
    /// infrastructure between the client and the service. Synthesized
    /// client-side; not directly representable on the wire.
    case unrecognizedResponse(status: Int, text: String)

    /// End-user-facing message attached to this error, if any. Pulled from
    /// whichever of the variants below carries a `userMessage`. UIs should
    /// surface this verbatim where present.
    public var userMessage: String? {
        switch self {
        case .unexpectedError(let m), .invalidCredentials(let m),
            .unauthorized(let m), .accessExceeded(let m),
            .periodOutOfBounds(let m):
            return m
        case .serviceBlocked(_, let m), .unsupportedProduct(_, let m),
            .paymentFailed(_, let m), .providerError(_, let m):
            return m
        case .canceled, .interruptError, .notFound, .unexpectedValue, .ticketError,
            .unrecognizedResponse:
            return nil
        }
    }

    /// Build a ``RoutexError`` from an HTTP error response. A body carrying
    /// a known variant tag decodes to that variant (even on a 404), a 404
    /// without one is ``notFound``, and anything else is
    /// ``unrecognizedResponse(status:text:)``.
    package static func dispatch(status: Int, body: Data) -> RoutexError {
        if !body.isEmpty,
            let parsed = try? JSONDecoder().decode(RoutexError.self, from: body)
        {
            return parsed
        }
        if status == 404 {
            return .notFound
        }
        return .unrecognizedResponse(
            status: status,
            text: String(data: body, encoding: .utf8) ?? ""
        )
    }
}

extension RoutexError: CustomStringConvertible {
    /// Case name plus any code and end-user message, for logs.
    public var description: String {
        let base: String
        switch self {
        case .unexpectedError: base = "unexpectedError"
        case .canceled: base = "canceled"
        case .invalidCredentials: base = "invalidCredentials"
        case .serviceBlocked(let code, _):
            base = "serviceBlocked" + (code.map { "(\($0.rawValue))" } ?? "")
        case .unauthorized: base = "unauthorized"
        case .accessExceeded: base = "accessExceeded"
        case .periodOutOfBounds: base = "periodOutOfBounds"
        case .unsupportedProduct(let reason, _):
            base = "unsupportedProduct" + (reason.map { "(\($0.rawValue))" } ?? "")
        case .paymentFailed(let code, _):
            base = "paymentFailed" + (code.map { "(\($0.rawValue))" } ?? "")
        case .unexpectedValue(let error): base = "unexpectedValue(\(error))"
        case .ticketError(let error, let code): base = "ticketError(\(code.rawValue), \(error))"
        case .providerError(let code, _):
            base = "providerError" + (code.map { "(\($0.rawValue))" } ?? "")
        case .interruptError: base = "interruptError"
        case .notFound: base = "notFound"
        case .unrecognizedResponse(let status, let text):
            base = "unrecognizedResponse(status: \(status), text: \(text))"
        }
        guard let message = userMessage else { return base }
        return "\(base): \(message)"
    }
}

extension RoutexError: LocalizedError {
    public var errorDescription: String? { description }
}

// MARK: - Wire encoding (externally tagged enum)

extension RoutexError: Codable {
    private enum Tag: String, CodingKey {
        case unexpectedError = "UnexpectedError"
        case canceled = "Canceled"
        case invalidCredentials = "InvalidCredentials"
        case serviceBlocked = "ServiceBlocked"
        case unauthorized = "Unauthorized"
        case accessExceeded = "AccessExceeded"
        case periodOutOfBounds = "PeriodOutOfBounds"
        case unsupportedProduct = "UnsupportedProduct"
        case paymentFailed = "PaymentFailed"
        case unexpectedValue = "UnexpectedValue"
        case ticketError = "TicketError"
        case providerError = "ProviderError"
        case interruptError = "InterruptError"
        // notFound and unrecognizedResponse have no wire variants; both are
        // synthesized client-side from the HTTP response.
    }

    private struct UserMessageOnly: Codable, Sendable { var userMessage: String? }
    private struct ServiceBlockedFields: Codable, Sendable {
        var code: ServiceBlockedCode?
        var userMessage: String?
    }
    private struct UnsupportedProductFields: Codable, Sendable {
        var reason: UnsupportedProductReason?
        var userMessage: String?
    }
    private struct PaymentFailedFields: Codable, Sendable {
        var code: PaymentErrorCode?
        var userMessage: String?
    }
    private struct ProviderErrorFields: Codable, Sendable {
        var code: ProviderErrorCode?
        var userMessage: String?
    }
    private struct UnexpectedValueFields: Codable, Sendable { var error: String }
    private struct TicketErrorFields: Codable, Sendable {
        var error: String
        var code: TicketErrorCode
    }
    private struct EmptyFields: Codable, Sendable {}

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: Tag.self)
        guard container.allKeys.count == 1, let tag = container.allKeys.first else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription:
                        "Expected exactly one tag for RoutexError; got \(container.allKeys)"
                )
            )
        }
        switch tag {
        case .unexpectedError:
            let f = try container.decode(UserMessageOnly.self, forKey: tag)
            self = .unexpectedError(userMessage: f.userMessage)
        case .canceled:
            _ = try container.decode(EmptyFields.self, forKey: tag)
            self = .canceled
        case .invalidCredentials:
            let f = try container.decode(UserMessageOnly.self, forKey: tag)
            self = .invalidCredentials(userMessage: f.userMessage)
        case .serviceBlocked:
            let f = try container.decode(ServiceBlockedFields.self, forKey: tag)
            self = .serviceBlocked(code: f.code, userMessage: f.userMessage)
        case .unauthorized:
            let f = try container.decode(UserMessageOnly.self, forKey: tag)
            self = .unauthorized(userMessage: f.userMessage)
        case .accessExceeded:
            let f = try container.decode(UserMessageOnly.self, forKey: tag)
            self = .accessExceeded(userMessage: f.userMessage)
        case .periodOutOfBounds:
            let f = try container.decode(UserMessageOnly.self, forKey: tag)
            self = .periodOutOfBounds(userMessage: f.userMessage)
        case .unsupportedProduct:
            let f = try container.decode(UnsupportedProductFields.self, forKey: tag)
            self = .unsupportedProduct(reason: f.reason, userMessage: f.userMessage)
        case .paymentFailed:
            let f = try container.decode(PaymentFailedFields.self, forKey: tag)
            self = .paymentFailed(code: f.code, userMessage: f.userMessage)
        case .unexpectedValue:
            let f = try container.decode(UnexpectedValueFields.self, forKey: tag)
            self = .unexpectedValue(error: f.error)
        case .ticketError:
            let f = try container.decode(TicketErrorFields.self, forKey: tag)
            self = .ticketError(error: f.error, code: f.code)
        case .providerError:
            let f = try container.decode(ProviderErrorFields.self, forKey: tag)
            self = .providerError(code: f.code, userMessage: f.userMessage)
        case .interruptError:
            _ = try container.decode(EmptyFields.self, forKey: tag)
            self = .interruptError
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: Tag.self)
        switch self {
        case .unexpectedError(let m):
            try container.encode(UserMessageOnly(userMessage: m), forKey: .unexpectedError)
        case .canceled:
            try container.encode(EmptyFields(), forKey: .canceled)
        case .invalidCredentials(let m):
            try container.encode(UserMessageOnly(userMessage: m), forKey: .invalidCredentials)
        case .serviceBlocked(let code, let m):
            try container.encode(
                ServiceBlockedFields(code: code, userMessage: m),
                forKey: .serviceBlocked
            )
        case .unauthorized(let m):
            try container.encode(UserMessageOnly(userMessage: m), forKey: .unauthorized)
        case .accessExceeded(let m):
            try container.encode(UserMessageOnly(userMessage: m), forKey: .accessExceeded)
        case .periodOutOfBounds(let m):
            try container.encode(UserMessageOnly(userMessage: m), forKey: .periodOutOfBounds)
        case .unsupportedProduct(let reason, let m):
            try container.encode(
                UnsupportedProductFields(reason: reason, userMessage: m),
                forKey: .unsupportedProduct
            )
        case .paymentFailed(let code, let m):
            try container.encode(
                PaymentFailedFields(code: code, userMessage: m),
                forKey: .paymentFailed
            )
        case .unexpectedValue(let err):
            try container.encode(UnexpectedValueFields(error: err), forKey: .unexpectedValue)
        case .ticketError(let err, let code):
            try container.encode(TicketErrorFields(error: err, code: code), forKey: .ticketError)
        case .providerError(let code, let m):
            try container.encode(
                ProviderErrorFields(code: code, userMessage: m),
                forKey: .providerError
            )
        case .interruptError:
            try container.encode(EmptyFields(), forKey: .interruptError)
        case .notFound, .unrecognizedResponse:
            // Not directly representable on the wire - synthesized from the
            // HTTP response. Refuse to encode.
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "\(self) is synthesized client-side and has no wire form"
                )
            )
        }
    }
}
