import Foundation

/// The IPv4 address websites see, from Cloudflare's trace page.
struct IPCheck: Hashable {
    var ip: String
    var country: String
    var colo: String

    /// "United Kingdom · LHR": the country, and the airport code of the Cloudflare data centre that answered.
    var place: String {
        let name = Locale.current.localizedString(forRegionCode: country) ?? country
        return [name, colo].filter { !$0.isEmpty }.joined(separator: " · ")
    }

    /// The country's flag emoji; nil for Cloudflare's "XX" (unknown) and "T1" (Tor).
    var flag: String? {
        let code = country.uppercased().unicodeScalars
        guard code.count == 2, code.allSatisfy({ ("A"..."Z").contains($0) }), country.uppercased() != "XX" else { return nil }
        return String(String.UnicodeScalarView(code.compactMap { UnicodeScalar(0x1F1E6 + $0.value - 65) }))
    }

    enum Result: Equatable {
        case found(IPCheck)
        case unreachable
    }

    static func run() async -> Result {
        // A fresh session each time: a pooled connection from before the tunnel came up would report the old address.
        let session = URLSession(configuration: .ephemeral)
        defer { session.finishTasksAndInvalidate() }
        let req = URLRequest(url: URL(string: "https://1.1.1.1/cdn-cgi/trace")!, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 6)
        guard let (data, resp) = try? await session.data(for: req),
              (resp as? HTTPURLResponse)?.statusCode == 200,
              let text = String(data: data, encoding: .utf8)
        else { return .unreachable }
        var fields: [String: String] = [:]
        for line in text.split(separator: "\n") {
            let kv = line.split(separator: "=", maxSplits: 1)
            if kv.count == 2 { fields[String(kv[0])] = String(kv[1]) }
        }
        guard let ip = fields["ip"] else { return .unreachable }
        return .found(IPCheck(ip: ip, country: fields["loc"] ?? "", colo: fields["colo"] ?? ""))
    }
}
