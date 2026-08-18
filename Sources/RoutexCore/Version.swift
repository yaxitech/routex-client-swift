// Hand-maintained client version. Bumped per release; the value is stamped
// into the User-Agent header and shipped to YAXI for telemetry.

enum Version {
    static let major = 0
    static let minor = 5
    static let patch = 0
    static let versionString = "\(major).\(minor).\(patch)"
}
