import Foundation
import Security

/// What GET {API}/profile returns. Mirrors internal/profile.Profile.
struct Profile: Codable, Equatable {
    struct WireGuard: Codable, Equatable {
        var port: Int
        var serverPublicKey: String
        var address: [String]
        var dns: [String]
        var mtu: Int
    }
    /// WireGuard with junk packets and custom headers; same keys and addresses as `wireguard`.
    struct AmneziaWG: Codable, Equatable {
        var port: Int
        var address: [String]
        var jc, jmin, jmax, s1, s2: Int
        var h1, h2, h3, h4: UInt32
    }
    struct Reality: Codable, Equatable {
        var port: Int
        var uuid: String
        var publicKey: String
        var shortId: String
        /// Reality Mux: the same keys without Vision, multiplexed.
        var muxPort: Int?
    }
    struct Hysteria2: Codable, Equatable {
        var port: Int
        var auth: String
        var pinSHA256: String?
        /// Hysteria2 Obfs: Salamander on its own port, hopping across `hopPorts`.
        struct Obfs: Codable, Equatable {
            var port: Int
            var password: String
            var hopPorts: String?
        }
        var obfs: Obfs?
    }
    /// For iOS's built-in IKEv2 client (NEVPNManager), not the Go tunnel.
    struct IKEv2: Codable, Equatable {
        var server: String
        var remoteId: String
        var username: String
        var password: String
    }
    var host: String
    var wireguard: WireGuard
    var amneziawg: AmneziaWG?
    var reality: Reality
    var hysteria2: Hysteria2?
    var ikev2: IKEv2?
    /// The device's OpenVPN identity (PEM), for the Go tunnel. The same .ovpn is
    /// at GET {API}/openvpn, for OpenVPN Connect.
    struct OpenVPN: Codable, Equatable {
        var port: Int
        var ca, cert, key, tlsCrypt: String?
    }
    var openvpn: OpenVPN?
    /// An AnyConnect login (ocserv), for the Go tunnel or Cisco Secure Client.
    struct OpenConnect: Codable, Equatable {
        var server: String
        var port: Int
        var username: String
        var password: String
        /// Sent as the first request's query; without it ocserv answers 404.
        var secret: String?
    }
    var openconnect: OpenConnect?
    /// HTTP/2 CONNECT on the website.
    struct TrustTunnel: Codable, Equatable {
        var port: Int
        var username: String
        var password: String
    }
    var trusttunnel: TrustTunnel?
    struct AnyTLS: Codable, Equatable {
        var port: Int
        var password: String
    }
    var anytls: AnyTLS?
    struct Mieru: Codable, Equatable {
        var port: Int
        var username: String
        var password: String
    }
    var mieru: Mieru?
    /// VLESS over WebSocket to the website's name behind Cloudflare's proxy.
    struct Cloudflare: Codable, Equatable {
        var host: String
        var port: Int
        var path: String
        /// Cloudflare's addresses for `host`, so no DNS is needed first.
        var addresses: [String]?
        var pinSHA256: String?
    }
    var cloudflare: Cloudflare?
    /// The server's own addresses, for when its name doesn't resolve.
    var ips: [String]?
    /// Relays forward every protocol's port to the server from another country.
    struct Relay: Codable, Equatable {
        var address: String
        var country: String
    }
    var relays: [Relay]?
    /// The device's second login, whose traffic leaves the server through the
    /// first relay (the exit route).
    struct Exit: Codable, Equatable {
        var uuid: String
        var hysteriaAuth: String
        var username: String
        var anytlsPassword: String
    }
    var exit: Exit?
}

/// The way to the server: nomaxcore's Route constants.
enum TunnelRoute: String, CaseIterable, Identifiable {
    case auto, direct, relay, exit
    var id: String { rawValue }
    var title: String {
        switch self {
        case .auto: "Auto"
        case .direct: "Direct"
        case .relay: "Via relay"
        case .exit: "Relay exit"
        }
    }

    /// `builtInRelays` stands in for the profile's before joining.
    func isOffered(by p: Profile?, builtInRelays: Bool = false) -> Bool {
        switch self {
        case .auto, .direct: true
        case .relay: p.map { !($0.relays ?? []).isEmpty } ?? builtInRelays
        case .exit: p?.exit != nil
        }
    }
}

/// The enrolment, shared between the app and the tunnel through one keychain access group.
struct Enrollment: Codable {
    var profile: Profile
    var deviceToken: String
    var wgPrivateKey: String
}

/// One step of a connection run, from the Go core (core/events.go). A run
/// starts with "start" (proto auto, test or the protocol picked, and `order`;
/// `reconnect` when the core began it to replace a tunnel that stopped carrying
/// traffic), each protocol goes "trying" then "ok" or "fail", and "done" names
/// the protocol that connected, or none. Steps never contain keys or passwords.
struct RunEvent: Codable, Hashable {
    var seq: Int64
    /// Unix milliseconds.
    var t: Int64
    var run: Int64
    var proto: String?
    var state: String
    var step: String
    var order: [String]?
    var reconnect: Bool?
}

/// What the tunnel keeps between runs: the order Auto learned ("worked,…|failed,…";
/// older versions kept just the protocol that last got through), which the next
/// Auto takes, and the last run's steps, for when the app wasn't open.
struct RunSummary: Codable {
    var lastGood: String?
    var events: [RunEvent] = []
}

/// The choices in the protocol menu. After Auto they're in the order Auto tries
/// them (internal/profile.Protocols); IKEv2 is the system's own client.
enum TunnelProtocol: String, CaseIterable, Identifiable {
    case auto, wireguard, amneziawg, hysteria2, hysteria2obfs, openvpn, mieru, trusttunnel, openconnect,
         realitymux, anytls, reality, cloudflare, ikev2
    var id: String { rawValue }
    var title: String {
        switch self {
        case .auto: "Auto"
        case .wireguard: "WireGuard"
        case .amneziawg: "AmneziaWG"
        case .hysteria2: "Hysteria2"
        case .hysteria2obfs: "Hysteria2 Obfs"
        case .openvpn: "OpenVPN"
        case .mieru: "Mieru"
        case .trusttunnel: "TrustTunnel"
        case .openconnect: "Cisco AnyConnect"
        case .realitymux: "Reality Mux"
        case .anytls: "AnyTLS"
        case .reality: "Reality"
        case .cloudflare: "Cloudflare"
        case .ikev2: "IKEv2"
        }
    }

    /// The exit route has only the protocols Xray carries.
    func isOffered(by p: Profile, route: TunnelRoute) -> Bool {
        if route == .exit, [.wireguard, .amneziawg, .openvpn, .openconnect, .ikev2].contains(self) { return false }
        return isOffered(by: p)
    }

    func isOffered(by p: Profile) -> Bool {
        switch self {
        case .amneziawg: p.amneziawg != nil
        case .hysteria2: p.hysteria2 != nil
        case .hysteria2obfs: p.hysteria2?.obfs != nil
        case .openvpn: p.openvpn?.cert != nil
        case .mieru: p.mieru != nil
        case .trusttunnel: p.trusttunnel != nil
        case .openconnect: p.openconnect != nil
        case .realitymux: (p.reality.muxPort ?? 0) != 0
        case .anytls: p.anytls != nil
        case .cloudflare: p.cloudflare != nil
        case .ikev2: p.ikev2 != nil
        case .auto, .wireguard, .reality: true
        }
    }
}

enum Keychain {
    private static let service = "com.example.nomax"
    private static let account = "enrollment"

    private static var group: String? {
        Bundle.main.object(forInfoDictionaryKey: "KeychainGroup") as? String
    }

    private static func query(_ account: String = account) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        if let group, !group.hasPrefix("$(") {
            q[kSecAttrAccessGroup as String] = group
        }
        #if os(macOS)
        // The iOS-style keychain, so the app and the tunnel can share items by access group.
        q[kSecUseDataProtectionKeychain as String] = true
        #endif
        return q
    }

    static func load() -> Enrollment? {
        read(account).flatMap { try? JSONDecoder().decode(Enrollment.self, from: $0) }
    }

    @discardableResult
    static func save(_ e: Enrollment) -> Bool {
        guard let data = try? JSONEncoder().encode(e) else { return false }
        return write(data, account)
    }

    static func loadRun() -> RunSummary? {
        read("run").flatMap { try? JSONDecoder().decode(RunSummary.self, from: $0) }
    }

    static func saveRun(_ s: RunSummary) {
        if let data = try? JSONEncoder().encode(s) { write(data, "run") }
    }

    static func clear() {
        SecItemDelete(query() as CFDictionary)
        SecItemDelete(query("run") as CFDictionary)
        SecItemDelete(passwordQuery() as CFDictionary)
    }

    private static func read(_ account: String) -> Data? {
        var q = query(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess else { return nil }
        return out as? Data
    }

    @discardableResult
    private static func write(_ data: Data, _ account: String) -> Bool {
        let attrs: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let status = SecItemUpdate(query(account) as CFDictionary, attrs as CFDictionary)
        if status == errSecItemNotFound {
            return SecItemAdd(query(account).merging(attrs) { $1 } as CFDictionary, nil) == errSecSuccess
        }
        return status == errSecSuccess
    }

    private static func passwordQuery() -> [String: Any] {
        var q = query()
        q[kSecAttrAccount as String] = "ikev2"
        return q
    }

    /// Stores the IKEv2 password and returns the persistent reference NEVPNProtocolIKEv2 wants.
    static func ikev2PasswordRef(_ password: String) -> Data? {
        let q = passwordQuery()
        SecItemDelete(q as CFDictionary)
        var add = q
        add[kSecValueData as String] = Data(password.utf8)
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        add[kSecReturnPersistentRef as String] = true
        var ref: CFTypeRef?
        guard SecItemAdd(add as CFDictionary, &ref) == errSecSuccess else { return nil }
        return ref as? Data
    }
}
