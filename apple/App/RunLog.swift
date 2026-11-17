import Foundation
import Observation
#if os(iOS)
import UIKit
#endif

/// One line of the log: a step from the tunnel, or something the app did (run 0).
struct LogLine: Codable, Hashable {
    var t: Date
    var run: Int64
    var proto: String?
    var state: String
    var step: String

    init(t: Date = .now, run: Int64 = 0, proto: String? = nil, state: String = "info", step: String) {
        (self.t, self.run, self.proto, self.state, self.step) = (t, run, proto, state, step)
    }

    init(_ e: RunEvent) {
        self.init(t: Date(timeIntervalSince1970: Double(e.t) / 1000), run: e.run, proto: e.proto, state: e.state, step: e.step)
    }
}

/// The log, kept as JSON lines in Application Support and capped at `cap` lines.
@MainActor
@Observable
final class LogStore {
    private(set) var lines: [LogLine] = []
    /// The newest tunnel step seen, so polling asks only for later ones.
    private(set) var lastSeq: Int64

    private static let cap = 2000
    private let url: URL

    init() {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        url = dir.appending(path: "nomax-log.jsonl")
        lastSeq = Int64(UserDefaults.standard.integer(forKey: "logSeq"))
        if let text = try? String(contentsOf: url, encoding: .utf8) {
            let decoder = JSONDecoder()
            lines = text.split(separator: "\n").compactMap { try? decoder.decode(LogLine.self, from: Data($0.utf8)) }
        }
    }

    /// Adds the tunnel's steps that are newer than any seen; returns them.
    @discardableResult
    func add(_ events: [RunEvent]) -> [RunEvent] {
        let new = events.filter { $0.seq > lastSeq }.sorted { $0.seq < $1.seq }
        guard let last = new.last else { return [] }
        lastSeq = last.seq
        UserDefaults.standard.set(Int(lastSeq), forKey: "logSeq")
        append(new.map(LogLine.init))
        return new
    }

    func app(_ step: String) {
        append([LogLine(step: step)])
    }

    func clear() {
        lines = []
        try? FileManager.default.removeItem(at: url)
    }

    private func append(_ new: [LogLine]) {
        lines += new
        let encoder = JSONEncoder()
        if lines.count > Self.cap + Self.cap / 4 {
            lines.removeFirst(lines.count - Self.cap)
            let text = lines.compactMap { try? encoder.encode($0) }.map { String(decoding: $0, as: UTF8.self) }.joined(separator: "\n") + "\n"
            try? text.write(to: url, atomically: true, encoding: .utf8)
            return
        }
        let text = new.compactMap { try? encoder.encode($0) }.map { String(decoding: $0, as: UTF8.self) + "\n" }.joined()
        if let h = try? FileHandle(forWritingTo: url) {
            defer { try? h.close() }
            _ = try? h.seekToEnd()
            try? h.write(contentsOf: Data(text.utf8))
        } else {
            try? text.write(to: url, atomically: true, encoding: .utf8)
        }
    }

    /// Runs of consecutive lines, newest first; the app's own lines form their own groups.
    struct Section: Identifiable {
        let id: Int
        let run: Int64
        let lines: [LogLine]
        var title: String {
            run == 0 ? "App" : (lines.first { $0.state == "start" }?.step ?? "Tunnel")
        }
        var start: Date { lines.first?.t ?? .distantPast }
    }

    /// A section per run, newest first. The tunnel's steps for a run stay together
    /// even when the app logged something meanwhile; the app's lines get sections of their own.
    var sections: [Section] {
        var groups: [(run: Int64, lines: [LogLine])] = []
        var byRun: [Int64: Int] = [:]
        for line in lines {
            if line.run != 0, let i = byRun[line.run] {
                groups[i].lines.append(line)
            } else if line.run == 0, groups.last?.run == 0 {
                groups[groups.count - 1].lines.append(line)
            } else {
                if line.run != 0 { byRun[line.run] = groups.count }
                groups.append((line.run, [line]))
            }
        }
        return groups.enumerated().map { Section(id: $0.offset, run: $0.element.run, lines: $0.element.lines) }.reversed()
    }

    /// "NoMax 1.0.0 (33) · iPhone, iOS 26.1": the app and device, for what gets shared.
    static var appInfo: String {
        let info = Bundle.main.infoDictionary
        let version = "\(info?["CFBundleShortVersionString"] as? String ?? "?") (\(info?["CFBundleVersion"] as? String ?? "?"))"
        #if os(iOS)
        let device = "\(UIDevice.current.model), iOS \(UIDevice.current.systemVersion)"
        #else
        let device = "Mac, macOS \(ProcessInfo.processInfo.operatingSystemVersionString)"
        #endif
        return "NoMax \(version) · \(device)"
    }

    /// The log as plain text, newest run first, ready to paste into a chat.
    func text(choice: TunnelProtocol) -> String {
        var out = "\(Self.appInfo) · protocol \(choice.title)\n"
        let day = Date.FormatStyle().day().month(.abbreviated).hour().minute()
        let time = Date.FormatStyle().hour(.twoDigits(amPM: .omitted)).minute(.twoDigits).second(.twoDigits)
        for s in sections {
            out += "\n— \(s.start.formatted(day)) · \(s.title)\n"
            for l in s.lines {
                let name = l.proto.map(LogStore.title) ?? ""
                out += "\(l.t.formatted(time)) \(LogStore.mark(l.state)) \(name.isEmpty ? "" : name + ": ")\(l.step)\n"
            }
        }
        return out
    }

    nonisolated static func title(_ proto: String) -> String {
        proto == "test" ? "Test" : TunnelProtocol(rawValue: proto)?.title ?? proto
    }

    nonisolated static func mark(_ state: String) -> String {
        switch state {
        case "ok": "✓"
        case "fail": "✗"
        case "trying": "…"
        case "start": "▶"
        case "done": "■"
        default: "·"
        }
    }
}

/// An Auto or Test run as the run card shows it: a row per protocol.
struct RunState: Equatable {
    enum Kind { case auto, test, single }
    enum RowState { case pending, trying, ok, fail }

    struct Row: Identifiable, Equatable {
        let proto: String
        var state: RowState = .pending
        var step = ""
        var id: String { proto }
        var title: String { LogStore.title(proto) }
    }

    let id: Int64
    let kind: Kind
    var rows: [Row]
    var headline: String
    var finished = false
    /// The protocol that connected, once the run is done.
    var winner: String?

    var failed: Bool { finished && winner == nil }
    var active: String? { rows.last { $0.state == .trying }?.proto }
    var tried: Int { rows.filter { $0.state != .pending }.count }

    /// A new run, from its start event.
    init?(_ e: RunEvent) {
        guard e.state == "start" else { return nil }
        id = e.run
        kind = switch e.proto ?? "" {
        case TunnelProtocol.auto.rawValue: .auto
        case "test": .test
        default: .single
        }
        rows = (e.order ?? []).map { Row(proto: $0) }
        headline = e.step
    }

    mutating func apply(_ e: RunEvent) {
        guard e.run == id else { return }
        let i = e.proto.flatMap { p in rows.firstIndex { $0.proto == p } }
        switch e.state {
        case "trying", "ok", "fail":
            guard let i else { return }
            rows[i].state = e.state == "ok" ? .ok : e.state == "fail" ? .fail : .trying
            rows[i].step = e.step
        case "done":
            finished = true
            winner = e.proto.flatMap { $0.isEmpty ? nil : $0 }
            headline = e.step
        case "info":
            if let i { rows[i].step = e.step } else if !finished { headline = e.step }
        default:
            break
        }
    }
}
