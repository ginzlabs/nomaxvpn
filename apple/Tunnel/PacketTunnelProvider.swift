import NomaxCore
import Network
import NetworkExtension

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let queue = DispatchQueue(label: "com.example.nomax.tunnel")
    private var pathMonitor: NWPathMonitor?
    /// Follows the core's steps while the tunnel is up. `lastSeq` and
    /// `reconnect` are only used on `followQueue`.
    private let followQueue = DispatchQueue(label: "com.example.nomax.follow")
    private var follower: DispatchSourceTimer?
    private var lastSeq: Int64 = 0
    private var reconnect: (run: Int64, auto: Bool)?
    /// Refreshes the saved profile while the tunnel is up, as the app may not
    /// open for days. A call can take up to a minute, so it has its own queue.
    private let refreshQueue = DispatchQueue(label: "com.example.nomax.refresh")
    private var refresher: DispatchSourceTimer?
    /// Set by `stopTunnel`. A stop before the core's run began has nothing to
    /// cancel, so the start checks this instead.
    private let stopping = NSLock()
    private var stopped = false
    private var isStopped: Bool {
        stopping.lock()
        defer { stopping.unlock() }
        return stopped
    }

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        guard let enrollment = Keychain.load() else {
            completionHandler(TunnelError.notEnrolled)
            return
        }
        let config = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        let proto = (options?["protocol"] as? String) ?? (config?["protocol"] as? String) ?? TunnelProtocol.auto.rawValue
        let route = (options?["route"] as? String) ?? (config?["route"] as? String) ?? TunnelRoute.auto.rawValue
        let profileJSON = (try? JSONEncoder().encode(enrollment.profile)).flatMap { String(data: $0, encoding: .utf8) } ?? ""

        queue.async {
            let endpoint = NomaxcoreEndpoint(profileJSON)
            if endpoint.isEmpty {
                completionHandler(TunnelError.noAddress(enrollment.profile.host))
                return
            }
            self.setTunnelNetworkSettings(Self.settings(enrollment.profile, endpoint: endpoint)) { error in
                if let error {
                    completionHandler(error)
                    return
                }
                self.queue.async {
                    if self.isStopped {
                        completionHandler(CocoaError(.userCancelled))
                        return
                    }
                    let preferred = Keychain.loadRun()?.lastGood ?? ""
                    var error: NSError?
                    _ = NomaxcoreStart(profileJSON, proto, route, preferred, enrollment.wgPrivateKey, -1, endpoint, &error)
                    Self.remember(protocol: proto)
                    if let error {
                        completionHandler(error)
                        return
                    }
                    self.watchPath()
                    self.follow()
                    self.refreshEvery(hours: 6, route: route)
                    completionHandler(nil)
                }
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        pathMonitor?.cancel()
        pathMonitor = nil
        follower?.cancel()
        follower = nil
        refresher?.cancel()
        refresher = nil
        stopping.lock()
        stopped = true
        stopping.unlock()
        // An Auto run holds the queue; cancelling it first lets Stop through.
        NomaxcoreCancel()
        queue.async {
            NomaxcoreStop()
            completionHandler()
        }
    }

    /// "stats", or "events:N" for the run steps after seq N.
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        let message = String(data: messageData, encoding: .utf8) ?? ""
        if message == "stats" {
            completionHandler?(Data(NomaxcoreStats().utf8))
        } else if message.hasPrefix("events:") {
            completionHandler?(Data(NomaxcoreEvents(Int64(message.dropFirst(7)) ?? 0).utf8))
        } else {
            completionHandler?(nil)
        }
    }

    /// Keeps the run's steps for the app, and after Auto or Test the order the
    /// core learned, for the next Auto.
    private static func remember(protocol proto: String) {
        let events = (try? JSONDecoder().decode([RunEvent].self, from: Data(NomaxcoreEvents(0).utf8))) ?? []
        var summary = Keychain.loadRun() ?? RunSummary()
        if let run = events.last?.run {
            summary.events = Array(events.filter { $0.run == run }.suffix(150))
        }
        if proto == TunnelProtocol.auto.rawValue || proto == "test" {
            summary.lastGood = NomaxcorePreferred()
        }
        Keychain.saveRun(summary)
    }

    /// The core replaces a tunnel that stops carrying traffic on its own. The
    /// system shows "Reconnecting…" until another protocol gets through, and
    /// the run is kept for the app as at the start.
    private func follow() {
        let t = DispatchSource.makeTimerSource(queue: followQueue)
        t.schedule(deadline: .now() + 1, repeating: 1)
        t.setEventHandler { [weak self] in self?.followEvents() }
        t.resume()
        follower = t
    }

    private func followEvents() {
        let events = (try? JSONDecoder().decode([RunEvent].self, from: Data(NomaxcoreEvents(lastSeq).utf8))) ?? []
        guard let last = events.last else { return }
        lastSeq = last.seq
        for e in events {
            if e.state == "start", e.reconnect == true {
                reconnect = (e.run, e.proto == TunnelProtocol.auto.rawValue)
                reasserting = true
            } else if e.state == "done", let r = reconnect, e.run == r.run {
                Self.remember(protocol: r.auto ? TunnelProtocol.auto.rawValue : "")
                if !(e.proto ?? "").isEmpty {
                    reconnect = nil
                    reasserting = false
                }
            }
        }
    }

    private func refreshEvery(hours: Double, route: String) {
        let t = DispatchSource.makeTimerSource(queue: refreshQueue)
        t.schedule(deadline: .now() + hours * 3600, repeating: hours * 3600)
        t.setEventHandler { Self.refreshProfile(route: route) }
        t.resume()
        refresher = t
    }

    /// The next start reads the profile from the keychain, so a new address or
    /// relay is used then. The app handles a removed device when it opens.
    private static func refreshProfile(route: String) {
        guard var e = Keychain.load() else { return }
        struct Answer: Decodable { var status: Int; var body: String }
        let relays = (e.profile.relays ?? []).map(\.address).joined(separator: ",")
        let via = route == TunnelRoute.relay.rawValue || route == TunnelRoute.exit.rawValue ? "relay" : ""
        var error: NSError?
        let json = NomaxcoreCall(e.profile.host, "GET", "profile", e.deviceToken, "", via, relays, &error)
        guard error == nil,
              let a = try? JSONDecoder().decode(Answer.self, from: Data(json.utf8)), a.status == 200,
              let p = try? JSONDecoder().decode(Profile.self, from: Data(a.body.utf8)), p != e.profile
        else { return }
        e.profile = p
        _ = Keychain.save(e)
    }

    private func watchPath() {
        let monitor = NWPathMonitor()
        var first = true
        monitor.pathUpdateHandler = { path in
            if first { first = false; return }
            if path.status == .satisfied { NomaxcoreBumpSockets() }
        }
        monitor.start(queue: queue)
        pathMonitor = monitor
    }

    private static func settings(_ p: Profile, endpoint: String) -> NEPacketTunnelNetworkSettings {
        let s = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: endpoint)
        let v4 = p.wireguard.address.compactMap(CIDR.init).filter { !$0.isV6 }
        let v6 = p.wireguard.address.compactMap(CIDR.init).filter(\.isV6)
        let ipv4 = NEIPv4Settings(addresses: v4.map(\.address), subnetMasks: v4.map(\.mask))
        ipv4.includedRoutes = [NEIPv4Route.default()]
        s.ipv4Settings = ipv4
        if !v6.isEmpty {
            let ipv6 = NEIPv6Settings(addresses: v6.map(\.address), networkPrefixLengths: v6.map { NSNumber(value: $0.prefix) })
            ipv6.includedRoutes = [NEIPv6Route.default()]
            s.ipv6Settings = ipv6
        }
        let dns = NEDNSSettings(servers: p.wireguard.dns)
        dns.matchDomains = [""]
        s.dnsSettings = dns
        s.mtu = NSNumber(value: p.wireguard.mtu > 0 ? p.wireguard.mtu : 1280)
        return s
    }
}

enum TunnelError: LocalizedError {
    case notEnrolled
    case noAddress(String)
    var errorDescription: String? {
        switch self {
        case .notEnrolled: "Open NoMax and enter your PIN first."
        case .noAddress(let host): "Can't find \(host)."
        }
    }
}

private struct CIDR {
    let address: String
    let prefix: Int
    var isV6: Bool { address.contains(":") }
    var mask: String {
        let bits = prefix == 0 ? 0 : UInt32.max << (32 - UInt32(prefix))
        return [24, 16, 8, 0].map { String((bits >> UInt32($0)) & 0xff) }.joined(separator: ".")
    }

    init?(_ s: String) {
        let parts = s.split(separator: "/")
        guard parts.count == 2, let p = Int(parts[1]) else { return nil }
        address = String(parts[0])
        prefix = p
    }
}
