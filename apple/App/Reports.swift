import Foundation
import NomaxCheck
import Observation

/// Send: the log's lines and the connection checks the server doesn't have yet,
/// in one report (internal/panel/report.go). When the server can't be reached
/// they wait, and go by themselves once the tunnel connects or the app opens.
@MainActor
@Observable
final class Reports {
    struct Check: Codable { var t: Int64; var text: String }

    struct Body: Encodable {
        struct Line: Encodable {
            var t: Int64, run: Int64, proto: String, state: String, step: String

            init(_ l: LogLine) {
                (t, run, proto, state, step) = (Int64(l.t.timeIntervalSince1970 * 1000), l.run, l.proto ?? "", l.state, l.step)
            }
        }

        var app: String
        var lines: [Line]
        var checks: [Check]
    }

    private(set) var sending = false
    /// The last outcome, and when.
    private(set) var message = ""
    private(set) var at = Date.distantPast
    /// A Send that couldn't reach the server yet.
    private(set) var pending = UserDefaults.standard.bool(forKey: "reportPending") {
        didSet { UserDefaults.standard.set(pending, forKey: "reportPending") }
    }

    private static let checksKept = 20
    private static let maxLines = 5000
    private let url: URL

    init() {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        url = dir.appending(path: "nomax-checks.json")
    }

    /// What the screens say about sending: the outcome for a minute, and while something waits to go.
    func note(at now: Date) -> String {
        if sending { return "Sending…" }
        if now.timeIntervalSince(at) < 60 { return message }
        return pending ? "Waiting to send. It goes by itself once you're connected." : ""
    }

    var checks: [Check] {
        (try? Data(contentsOf: url)).flatMap { try? JSONDecoder().decode([Check].self, from: $0) } ?? []
    }

    /// Keeps a finished connection check's report, unless it's the one kept last.
    func keep(check text: String) {
        var cs = checks
        guard !text.isEmpty, cs.last?.text != text else { return }
        cs.append(Check(t: Int64(Date.now.timeIntervalSince1970 * 1000), text: text))
        try? JSONEncoder().encode(Array(cs.suffix(Self.checksKept))).write(to: url, options: .atomic)
    }

    /// Sends what's newer than the last send. A quiet retry only speaks up once it got through.
    func send(_ lines: [LogLine], api: API, token: String, quiet: Bool) async {
        guard !sending else { return }
        sending = true
        if !quiet { (message, at) = ("Sending…", .now) }
        if let r = try? JSONDecoder().decode(CheckReport.self, from: Data(NomaxcheckState().utf8)), r.done {
            keep(check: NomaxcheckText())
        }
        let since = Int64(UserDefaults.standard.integer(forKey: "reportSent"))
        let new = Array(lines.map(Body.Line.init).filter { $0.t > since }.suffix(Self.maxLines))
        let checks = checks.filter { $0.t > since }
        var outcome: String
        var sent = false
        if new.isEmpty && checks.isEmpty {
            outcome = "Everything's sent already."
            pending = false
        } else {
            do {
                _ = try await api.report(token: token, Body(app: LogStore.appInfo, lines: new, checks: checks))
                let newest = max(new.map(\.t).max() ?? 0, checks.map(\.t).max() ?? 0)
                UserDefaults.standard.set(Int(newest), forKey: "reportSent")
                pending = false
                (outcome, sent) = ("Sent to NoMax. Thank you!", true)
            } catch let error as APIError {
                pending = false
                outcome = error.localizedDescription
            } catch {
                pending = true
                outcome = "Can't reach NoMax right now. It's saved here and goes by itself once you're connected."
            }
        }
        sending = false
        if !quiet || sent { (message, at) = (outcome, .now) }
    }
}
