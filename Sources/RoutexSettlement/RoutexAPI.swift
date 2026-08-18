import Foundation

/// Constants for the YAXI API level this client speaks.
package enum RoutexAPI {
    /// Sent as `Accept` on every request, key settlement included. A newer
    /// version is served a newer system version generation, so
    /// ``RoutexModels/LaunchMeasurement`` has to understand it first.
    package static let mediaType = "application/vnd.yaxi.v5"
}
