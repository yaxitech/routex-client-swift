// Wire-form bodies for each service request.

import Foundation
import RoutexModels

struct AccountsRequestBody: Encodable, Sendable {
    var credentials: Credentials
    var session: Session?
    var recurringConsents: Bool?
    var fields: [AccountField]
    var filter: AccountFilter?
}

struct BalancesRequestBody: Encodable, Sendable {
    var credentials: Credentials
    var session: Session?
    var recurringConsents: Bool?
    var accounts: [AccountReference]
}

struct TransactionsRequestBody: Encodable, Sendable {
    var credentials: Credentials
    var session: Session?
    var recurringConsents: Bool?
}

// Bodies of the services that also run without credentials. The server tells
// them apart from the ones above by the `connectionData` key; `session` and the
// service data fields carry over unchanged.

struct AccountsConnectionDataBody: Encodable, Sendable {
    var connectionData: ConnectionData
    var session: Session?
    var fields: [AccountField]
    var filter: AccountFilter?
}

struct BalancesConnectionDataBody: Encodable, Sendable {
    var connectionData: ConnectionData
    var session: Session?
    var accounts: [AccountReference]
}

struct TransactionsConnectionDataBody: Encodable, Sendable {
    var connectionData: ConnectionData
    var session: Session?
}

struct CollectPaymentRequestBody: Encodable, Sendable {
    var credentials: Credentials
    var session: Session?
    var recurringConsents: Bool?
    var account: DebtorAccountReference?
}

struct TransferRequestBody: Encodable, Sendable {
    var credentials: Credentials
    var session: Session?
    var recurringConsents: Bool?
    var product: PaymentProduct
    var debtorAccount: DebtorAccountReference?
    var debtorName: String?
    var requestedExecutionDate: ISODateTimeOrDate?
    var details: [TransferDetails]
}

/// Body of a `respond` continuation request.
struct RespondBody: Encodable, Sendable {
    var context: InputContext
    var response: String
}

/// Body of a `confirm` continuation request.
struct ConfirmBody: Encodable, Sendable {
    var context: ConfirmationContext
}

/// Body of a `registerRedirectURI` request.
struct RegisterRedirectBody: Encodable, Sendable {
    var handle: String
    var redirectURI: String

    private enum CodingKeys: String, CodingKey {
        case handle
        case redirectURI = "redirectUri"
    }
}

/// Server response shape for the `redirects` endpoint.
struct RedirectsResponse: Decodable, Sendable {
    var redirectURL: String

    private enum CodingKeys: String, CodingKey {
        case redirectURL = "redirectUrl"
    }
}
