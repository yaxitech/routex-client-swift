// Internal helper that parses the unverified JWT body of a ticket and
// extracts the ticket UUID and service tag. The signature is **not**
// verified; backends are responsible for verifying tickets before trusting
// their claims.

import Foundation

enum TicketDecoder {
    private struct Payload: Decodable {
        struct DataClaim: Decodable {
            var service: String
            var id: UUID
        }
        var data: DataClaim
    }

    static func parse(_ raw: String, expectingService service: String) throws -> UUID {
        let segments = raw.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count >= 2, let payload = Base64URL.decode(String(segments[1])) else {
            throw TicketParseError.malformedJWT
        }
        do {
            let p = try JSONDecoder().decode(Payload.self, from: payload)
            guard p.data.service == service else {
                throw TicketParseError.wrongService(expected: service, actual: p.data.service)
            }
            return p.data.id
        } catch let e as TicketParseError {
            throw e
        } catch {
            throw TicketParseError.missingDataClaim
        }
    }
}
