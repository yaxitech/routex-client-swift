import Foundation

/// Structure of a batch of transactions inside a parent ``Transaction``.
public struct BatchData: Sendable, Hashable, Codable {
    /// Number of transactions in the batch, if known.
    public let numberOfTransactions: UInt32?
    /// Details of transactions in the batch.
    ///
    /// Does not necessarily match a given number of transactions: it could
    /// be empty (no details given) or hold a single entry with common
    /// details on all transactions in the batch.
    public let transactions: [BatchTransactionDetails]

    /// Build a `BatchData`.
    public init(numberOfTransactions: UInt32? = nil, transactions: [BatchTransactionDetails] = []) {
        self.numberOfTransactions = numberOfTransactions
        self.transactions = transactions
    }
}
