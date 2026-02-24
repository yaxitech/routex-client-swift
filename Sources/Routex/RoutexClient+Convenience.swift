public extension RoutexClient {
    convenience init() {
        self.init(url: Url(string: "https://api.yaxi.tech")!)
    }

    convenience init(url: Url) {
        self.init(distribution: "Swift", version: "0.3.0", url: url)
    }
}
