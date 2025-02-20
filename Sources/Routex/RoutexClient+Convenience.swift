public extension RoutexClient {
    convenience init() {
        self.init(url: Url(string: "https://api.yaxi.tech")!)
    }

    convenience init(url: Url) {
        self.init(distribution: "Swift", version: "0.1.0", url: url)
    }
}
