import CryptoKit
import Foundation
import NetworkExtension
import NomaxCheck
import Observation

struct TunnelStats: Decodable {
    var `protocol`: String
    var rx: Int64
    var tx: Int64
    var handshake: Int64
}

@MainActor
@Observable
final class AppModel {
    var enrollment: Enrollment? = Keychain.load()
    var status: NEVPNStatus = .invalid
    var stats: TunnelStats?
    var connectedSince: Date?
    var error: String? {
        didSet { if let error, error != oldValue { log.app("Error: \(error)") } }
    }
    var busy = false
    let log = LogStore()
    let reports = Reports()
    /// The latest Auto, Test or single-protocol run, from the tunnel's steps.
    var run: RunState?
    /// Hides the run card until the next run starts.
    var runDismissed = false
    var pendingPIN: String?
    var ipResult: IPCheck.Result?
    var checkingIP = false

    var protocolChoice: TunnelProtocol {
        didSet {
            UserDefaults.standard.set(protocolChoice.rawValue, forKey: "protocol")
            Task { await saveManager() }
        }
    }

    var routeChoice: TunnelRoute {
        didSet {
            UserDefaults.standard.set(routeChoice.rawValue, forKey: "route")
            if let e = enrollment, !protocolChoice.isOffered(by: e.profile, route: routeChoice) { protocolChoice = .auto }
            Task { await saveManager() }
        }
    }

    var alwaysOn: Bool {
        didSet {
            UserDefaults.standard.set(alwaysOn, forKey: "alwaysOn")
            Task { await saveManager() }
        }
    }

    /// The Go tunnel, for every protocol except IKEv2, which uses iOS's own client.
    private var manager: NETunnelProviderManager?
    private let ikeManager = NEVPNManager.shared()
    private var statsTask: Task<Void, Never>?
    private var eventsTask: Task<Void, Never>?
    /// The first poll after launch asks for every step the tunnel has, so a run
    /// already under way still gets its card.
    private var polledEvents = false
    /// The last IP check's answer in the log, so reopening the app doesn't repeat it.
    private var loggedIP: String?
    private var ipTask: Task<Void, Never>?
    private let host = Bundle.main.object(forInfoDictionaryKey: "NomaxHost") as? String ?? "example.com"

    init() {
        protocolChoice = TunnelProtocol(rawValue: UserDefaults.standard.string(forKey: "protocol") ?? "") ?? .auto
        routeChoice = TunnelRoute(rawValue: UserDefaults.standard.string(forKey: "route") ?? "") ?? .auto
        alwaysOn = UserDefaults.standard.bool(forKey: "alwaysOn")
        NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.updateStatus() }
        }
    }

    var serverHost: String { enrollment?.profile.host ?? host }
    var api: API { API(host: serverHost, relays: enrollment?.profile.relays?.map(\.address) ?? [], route: routeChoice) }

    // MARK: VPN

    /// Protocols this server offers on the chosen route, for the picker.
    var protocols: [TunnelProtocol] {
        TunnelProtocol.allCases.filter { p in enrollment.map { p.isOffered(by: $0.profile, route: routeChoice) } ?? true }
    }

    /// The ways to the server this device has, for the picker.
    var routes: [TunnelRoute] {
        let builtIn = !NomaxcheckBuiltInRelays().isEmpty
        return TunnelRoute.allCases.filter { $0.isOffered(by: enrollment?.profile, builtInRelays: builtIn) }
    }

    private var usesIKEv2: Bool { protocolChoice == .ikev2 && enrollment?.profile.ikev2 != nil }
    private var connection: NEVPNConnection? { usesIKEv2 ? ikeManager.connection : manager?.connection }

    /// The protocol carrying traffic right now, when connected.
    var activeProtocol: TunnelProtocol? {
        usesIKEv2 ? .ikev2 : stats.flatMap { TunnelProtocol(rawValue: $0.protocol) }
    }

    func load() async {
        // Runs the tunnel made while the app was closed (always on, say).
        ingest(Keychain.loadRun()?.events ?? [])
        if run?.finished ?? true { runDismissed = true }
        let managers = (try? await NETunnelProviderManager.loadAllFromPreferences()) ?? []
        manager = managers.first
        try? await ikeManager.loadFromPreferences()
        updateStatus()
        Task { await refreshProfile() }
        if reports.pending { Task { await sendReports(quiet: true) } }
    }

    /// Sends the log and checks the server doesn't have yet.
    func sendReports(quiet: Bool = false) async {
        guard let e = enrollment else { return }
        await reports.send(log.lines, api: api, token: e.deviceToken, quiet: quiet)
    }

    private func updateStatus() {
        guard let conn = connection else {
            status = .invalid
            return
        }
        let old = status
        status = conn.status
        connectedSince = conn.connectedDate
        if status == .connected, !usesIKEv2 {
            startStats()
        } else {
            statsTask?.cancel()
            stats = nil
        }
        if !usesIKEv2, [.connecting, .connected, .reasserting, .disconnecting].contains(status) {
            startEvents()
        } else if eventsTask != nil {
            eventsTask?.cancel()
            eventsTask = nil
            // The tunnel saves its last steps before it stops.
            ingest(Keychain.loadRun()?.events ?? [])
        }
        if status != old {
            if old != .invalid { log.app(status.label) }
            ipResult = nil
            if status == .connected, reports.pending { Task { await sendReports(quiet: true) } }
            switch status {
            case .connected, .disconnected:
                checkIP(after: .seconds(1))
            case .invalid:
                ipTask?.cancel()
                checkingIP = false
            default:
                // A check follows once the tunnel settles.
                ipTask?.cancel()
                checkingIP = true
            }
        }
    }

    /// Asks Cloudflare which address websites see, after the routes have settled.
    func checkIP(after delay: Duration = .zero) {
        ipTask?.cancel()
        checkingIP = true
        ipTask = Task {
            try? await Task.sleep(for: delay)
            if Task.isCancelled { return }
            let result = await IPCheck.run()
            if Task.isCancelled { return }
            ipResult = result
            checkingIP = false
            let seen = switch result {
            case .found(let c): "Websites see \(c.ip), \(c.place)"
            case .unreachable: "IP check got no answer"
            }
            if seen != loggedIP { log.app(seen) }
            loggedIP = seen
        }
    }

    private func saveManager() async {
        if usesIKEv2 {
            await disable(manager)
            await saveIKEv2()
        } else {
            if ikeManager.protocolConfiguration != nil { await disable(ikeManager) }
            await saveTunnel()
        }
        updateStatus()
    }

    /// Only one VPN configuration may be enabled or on demand.
    private func disable(_ m: NEVPNManager?) async {
        guard let m, m.isEnabled || m.isOnDemandEnabled else { return }
        m.connection.stopVPNTunnel()
        m.isEnabled = false
        m.isOnDemandEnabled = false
        try? await m.saveToPreferences()
    }

    private var onDemandRules: [NEOnDemandRule] {
        let rule = NEOnDemandRuleConnect()
        rule.interfaceTypeMatch = .any
        return [rule]
    }

    private func saveIKEv2() async {
        guard let ike = enrollment?.profile.ikev2 else { return }
        guard let ref = Keychain.ikev2PasswordRef(ike.password) else {
            error = "Couldn't store the IKEv2 password in the keychain."
            return
        }
        let p = NEVPNProtocolIKEv2()
        // A relay forwards IKEv2's ports; the server's identity stays the same.
        p.serverAddress = routeChoice == .relay ? enrollment?.profile.relays?.first?.address ?? ike.server : ike.server
        p.remoteIdentifier = ike.remoteId
        p.localIdentifier = ike.username
        p.username = ike.username
        p.passwordReference = ref
        p.authenticationMethod = .none
        p.useExtendedAuthentication = true
        p.excludeLocalNetworks = true
        p.disconnectOnSleep = false
        p.enablePFS = true
        for sa in [p.ikeSecurityAssociationParameters, p.childSecurityAssociationParameters] {
            sa.encryptionAlgorithm = .algorithmAES256GCM
            sa.integrityAlgorithm = .SHA384
            sa.diffieHellmanGroup = .group20
        }
        ikeManager.protocolConfiguration = p
        ikeManager.localizedDescription = "NoMax (IKEv2)"
        ikeManager.isEnabled = true
        ikeManager.onDemandRules = onDemandRules
        ikeManager.isOnDemandEnabled = alwaysOn
        do {
            try await ikeManager.saveToPreferences()
            try await ikeManager.loadFromPreferences()
        } catch {
            self.error = "Couldn't save the VPN configuration: \(error.localizedDescription)"
        }
    }

    private func saveTunnel() async {
        guard let enrollment else { return }
        let m = manager ?? NETunnelProviderManager()
        let proto = (m.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
        proto.providerBundleIdentifier = "com.example.nomax.tunnel"
        proto.serverAddress = enrollment.profile.host
        proto.providerConfiguration = ["protocol": protocolChoice.rawValue, "route": routeChoice.rawValue]
        proto.excludeLocalNetworks = true
        m.protocolConfiguration = proto
        m.localizedDescription = "NoMax"
        m.isEnabled = true
        m.onDemandRules = onDemandRules
        m.isOnDemandEnabled = alwaysOn
        do {
            try await m.saveToPreferences()
            try await m.loadFromPreferences()
            manager = m
        } catch {
            self.error = "Couldn't save the VPN configuration: \(error.localizedDescription)"
        }
    }

    func toggle() async {
        error = nil
        switch status {
        case .connected, .connecting, .reasserting:
            if alwaysOn { alwaysOn = false }
            if run?.finished == false { runDismissed = true }
            log.app("Disconnect")
            connection?.stopVPNTunnel()
        default:
            // The last run's card goes until the new run's first step arrives.
            runDismissed = true
            log.app("Connect with \(protocolChoice.title)\(routeChoice == .auto ? "" : ", \(routeChoice.title)")")
            await connect()
        }
    }

    /// Tries every protocol, then connects with the quickest that worked.
    func testAll() async {
        error = nil
        log.app("Test every protocol")
        if protocolChoice == .ikev2 { protocolChoice = .auto }
        if let c = connection, ![.disconnected, .invalid].contains(c.status) {
            if alwaysOn { alwaysOn = false }
            c.stopVPNTunnel()
            for _ in 0..<50 {
                if [.disconnected, .invalid].contains(c.status) { break }
                try? await Task.sleep(for: .milliseconds(200))
            }
        }
        runDismissed = true
        await saveManager()
        do {
            try manager?.connection.startVPNTunnel(options: ["protocol": "test" as NSString, "route": routeChoice.rawValue as NSString])
        } catch {
            self.error = error.localizedDescription
        }
    }

    var testing: Bool { run.map { $0.kind == .test && !$0.finished } ?? false }

    func connect() async {
        await saveManager()
        do {
            if usesIKEv2 {
                try ikeManager.connection.startVPNTunnel()
            } else if let manager {
                try manager.connection.startVPNTunnel(options: ["protocol": protocolChoice.rawValue as NSString, "route": routeChoice.rawValue as NSString])
            }
        } catch {
            self.error = error.localizedDescription
        }
    }

    private func startStats() {
        statsTask?.cancel()
        statsTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.pollStats()
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    private func pollStats() async {
        if let data = await send("stats"), let s = try? JSONDecoder().decode(TunnelStats.self, from: data) { stats = s }
    }

    /// Follows the tunnel's run steps: quickly while it connects, slowly after.
    private func startEvents() {
        guard eventsTask == nil else { return }
        eventsTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                await self.pollEvents()
                let fast = self.status == .connecting || self.status == .reasserting
                try? await Task.sleep(for: fast ? .milliseconds(300) : .seconds(2))
            }
        }
    }

    private func pollEvents() async {
        guard let data = await send("events:\(polledEvents ? log.lastSeq : 0)"),
              let events = try? JSONDecoder().decode([RunEvent].self, from: data)
        else { return }
        polledEvents = true
        ingest(events)
    }

    /// Logs the steps not seen yet and updates the run card.
    private func ingest(_ events: [RunEvent]) {
        let fresh = Set(log.add(events).map(\.seq))
        for e in events.sorted(by: { $0.seq < $1.seq }) {
            if let r = RunState(e) {
                if r.id != run?.id {
                    run = r
                    if fresh.contains(e.seq) { runDismissed = false }
                }
            } else {
                run?.apply(e)
            }
            // A protocol picked by hand stays on when its traffic check fails.
            guard e.state == "done", run?.id == e.run, status == .connected else { continue }
            if (e.proto ?? "").isEmpty {
                if run?.kind == .single { error = noTraffic }
            } else if error == noTraffic {
                error = nil
            }
        }
    }

    private var noTraffic: String {
        "\(protocolChoice.title) is on, but nothing comes through it. Try Auto, or another protocol."
    }

    private func send(_ message: String) async -> Data? {
        guard let session = manager?.connection as? NETunnelProviderSession else { return nil }
        return await withCheckedContinuation { cont in
            do {
                try session.sendProviderMessage(Data(message.utf8)) { cont.resume(returning: $0) }
            } catch {
                cont.resume(returning: nil)
            }
        }
    }

    // MARK: Enrolment

    func enroll(pin: String, deviceName: String) async {
        busy = true
        error = nil
        defer { busy = false }
        let key = Curve25519.KeyAgreement.PrivateKey()
        do {
            let (token, profile) = try await API(host: host, route: routeChoice).enroll(
                pin: pin, deviceName: deviceName,
                wgPublicKey: key.publicKey.rawRepresentation.base64EncodedString())
            let e = Enrollment(profile: profile, deviceToken: token, wgPrivateKey: key.rawRepresentation.base64EncodedString())
            guard Keychain.save(e) else {
                error = "Couldn't store the enrolment in the keychain."
                return
            }
            enrollment = e
            await saveManager()
        } catch {
            self.error = error.localizedDescription
        }
    }

    func refreshProfile() async {
        guard var e = enrollment else { return }
        do {
            let p = try await api.profile(token: e.deviceToken)
            if p != e.profile {
                e.profile = p
                Keychain.save(e)
                enrollment = e
                log.app("Profile updated")
                if !routeChoice.isOffered(by: p) { routeChoice = .auto }
                if !protocolChoice.isOffered(by: p, route: routeChoice) { protocolChoice = .auto }
                await saveManager()
            }
        } catch APIError.unauthorized(let msg) {
            forget()
            error = msg
        } catch {
            // Offline or server unreachable: keep the cached profile.
            log.app("Couldn't refresh the profile: \(error.localizedDescription)")
        }
    }

    func leave() async {
        if let e = enrollment {
            try? await api.deleteDevice(token: e.deviceToken)
        }
        forget()
    }

    private func forget() {
        manager?.connection.stopVPNTunnel()
        if let manager { Task { try? await manager.removeFromPreferences() } }
        manager = nil
        if ikeManager.protocolConfiguration != nil {
            ikeManager.connection.stopVPNTunnel()
            Task { [ikeManager] in try? await ikeManager.removeFromPreferences() }
        }
        Keychain.clear()
        enrollment = nil
    }

    func handle(url: URL) {
        guard url.scheme == "nomax", url.host == "join",
              let pin = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems?.first(where: { $0.name == "pin" })?.value
        else { return }
        if enrollment == nil { pendingPIN = pin }
    }
}

enum APIError: LocalizedError {
    case server(String)
    case unauthorized(String)
    var errorDescription: String? {
        switch self {
        case .server(let m), .unauthorized(let m): m
        }
    }
}

/// The device API, through the server's address, a relay or the website's name
/// behind Cloudflare's proxy, whichever gets through (internal/apiclient).
/// No relays means the ones the app was built with.
struct API {
    let host: String
    var relays: [String] = []
    var route: TunnelRoute = .auto

    private struct EnrollResponse: Decodable {
        var deviceToken: String
        var profile: Profile
    }

    func enroll(pin: String, deviceName: String, wgPublicKey: String) async throws -> (String, Profile) {
        let body = try JSONEncoder().encode(["pin": pin, "deviceName": deviceName, "wgPublicKey": wgPublicKey])
        let r: EnrollResponse = try await call("POST", "enroll", body: body)
        return (r.deviceToken, r.profile)
    }

    func profile(token: String) async throws -> Profile {
        try await call("GET", "profile", token: token)
    }

    func deleteDevice(token: String) async throws {
        let _: Empty? = try? await call("DELETE", "device", token: token)
    }

    /// Sends log lines and connection checks; the server keeps each once and says how many were new.
    func report(token: String, _ body: Reports.Body) async throws -> Int {
        struct New: Decodable { var new: Int }
        let r: New = try await call("POST", "report", token: token, body: try JSONEncoder().encode(body))
        return r.new
    }

    private struct Empty: Decodable {}
    private struct ErrorBody: Decodable { var error: String }
    private struct Answer: Decodable {
        var status: Int
        var body: String
    }

    private func call<T: Decodable>(_ method: String, _ path: String, token: String? = nil, body: Data? = nil) async throws -> T {
        let (host, relays) = (host, relays.joined(separator: ","))
        let route = route == .relay || route == .exit ? "relay" : ""
        let text = body.flatMap { String(data: $0, encoding: .utf8) } ?? ""
        let answer = try await Task.detached {
            var error: NSError?
            let json = NomaxcheckCall(host, method, path, token ?? "", text, route, relays, &error)
            if let error { throw APIError.server(error.localizedDescription) }
            return try JSONDecoder().decode(Answer.self, from: Data(json.utf8))
        }.value
        let data = Data(answer.body.utf8)
        guard (200..<300).contains(answer.status) else {
            let msg = (try? JSONDecoder().decode(ErrorBody.self, from: data))?.error ?? "Server error (\(answer.status))."
            throw answer.status == 401 ? APIError.unauthorized(msg) : APIError.server(msg)
        }
        return try JSONDecoder().decode(T.self, from: data)
    }
}

extension NEVPNStatus {
    var label: String {
        switch self {
        case .connected: "Connected"
        case .connecting: "Connecting…"
        case .reasserting: "Reconnecting…"
        case .disconnecting: "Disconnecting…"
        default: "Not connected"
        }
    }
}
