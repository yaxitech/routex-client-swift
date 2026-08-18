import Foundation
import Testing

@testable import RoutexSettlement

@Suite("AMD root store: PEM parses cleanly")
struct AmdRootStoreSmokeTest {
    @Test func milanLoads() {
        let certs = AmdRootStore.byFamily[.milan]
        #expect(certs?.count == 2)
    }
    @Test func genoaLoads() {
        let certs = AmdRootStore.byFamily[.genoa]
        #expect(certs?.count == 2)
    }
    @Test func turinLoads() {
        let certs = AmdRootStore.byFamily[.turin]
        #expect(certs?.count == 2)
    }
}
