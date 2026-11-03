// Hand-maintained client version. Bumped per release; the value is stamped
// into the User-Agent header and shipped to YAXI for telemetry.

enum Version {
    static let major = 0
    static let minor = 6
    static let patch = 1
    static let versionString = "\(major).\(minor).\(patch)"
}
