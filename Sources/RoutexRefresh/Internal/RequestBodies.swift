// Wire-form bodies for each non-interactive service request. The service
// data fields sit alongside `connectionData`/`session` (the server flattens
// them into the same object).

import Foundation
import RoutexModels

struct NonInteractiveAccountsBody: Encodable, Sendable {
    var connectionData: ConnectionData
    var session: Session?
    var userInSession: UserInSession?
    var fields: [AccountField]
    var filter: AccountFilter?
}

struct NonInteractiveBalancesBody: Encodable, Sendable {
    var connectionData: ConnectionData
    var session: Session?
    var userInSession: UserInSession?
    var accounts: [AccountReference]
}

struct NonInteractiveTransactionsBody: Encodable, Sendable {
    var connectionData: ConnectionData
    var session: Session?
    var userInSession: UserInSession?
}
