import NomaxCheck
import SwiftUI

/// A connection check as nomaxcheck reports it.
struct CheckReport: Decodable, Equatable {
    struct Step: Decodable, Equatable, Identifiable {
        let id: String
        let group: String
        let title: String
        let state: String
        let detail: String?
    }

    var done = false
    var verdict: String?
    var steps: [Step] = []

    /// The steps by group, in the order the check lists them.
    var groups: [(name: String, steps: [Step])] {
        var out: [(name: String, steps: [Step])] = []
        for s in steps {
            if out.last?.name == s.group { out[out.count - 1].steps.append(s) } else { out.append((s.group, [s])) }
        }
        return out
    }
}

/// Checks how this network treats the server, shows each step as it finishes,
/// and lets the report be sent to whoever can help.
struct CheckView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var report = CheckReport()
    @State private var text = ""
    @State private var poll: Task<Void, Never>?

    var body: some View {
        NavigationStack {
            List {
                Section {
                    if report.done {
                        Text(report.verdict ?? "")
                    } else {
                        HStack(spacing: 10) {
                            ProgressView()
                            Text("Checking how this network treats our server…")
                        }
                    }
                } footer: {
                    Text("Sending shares this report and your log with us: your network's address and provider, and what reached our server. No keys or passwords.")
                }
                ForEach(report.groups, id: \.name) { g in
                    Section(g.name) {
                        ForEach(g.steps) { CheckRow(step: $0) }
                    }
                }
            }
            .animation(Brand.animation, value: report)
            .navigationTitle("Connection check")
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
                ToolbarItem(placement: .primaryAction) {
                    ShareLink(item: text).disabled(!report.done)
                }
            }
            .safeAreaInset(edge: .bottom) {
                SendFoot(canSend: report.done) {
                    Button(action: start) {
                        Text("Check again").bold()
                            .lineLimit(1).minimumScaleFactor(0.75)
                            .frame(maxWidth: .infinity, minHeight: 36)
                    }
                    .buttonStyle(.glassProminent)
                    .disabled(!report.done)
                }
            }
        }
        #if os(macOS)
        .frame(minWidth: 480, minHeight: 600)
        #endif
        .onAppear(perform: start)
        .onDisappear {
            poll?.cancel()
            NomaxcheckCancel()
        }
    }

    private func start() {
        NomaxcheckStart(model.serverHost, LogStore.appInfo)
        model.log.app("Connection check started")
        poll?.cancel()
        poll = Task {
            while !Task.isCancelled {
                if let r = try? JSONDecoder().decode(CheckReport.self, from: Data(NomaxcheckState().utf8)) {
                    report = r
                }
                if report.done {
                    text = NomaxcheckText()
                    model.log.app("Connection check: \(report.verdict ?? "")")
                    model.reports.keep(check: text)
                    return
                }
                try? await Task.sleep(for: .milliseconds(300))
            }
        }
    }
}

private struct CheckRow: View {
    let step: CheckReport.Step

    var body: some View {
        HStack(spacing: 12) {
            mark.frame(width: 20)
            VStack(alignment: .leading, spacing: 2) {
                Text(step.title)
                if let d = step.detail, !d.isEmpty {
                    Text(d)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
            }
        }
    }

    @ViewBuilder private var mark: some View {
        switch step.state {
        case "ok": Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
        case "fail": Image(systemName: "xmark.circle.fill").foregroundStyle(.red)
        case "info": Image(systemName: "info.circle.fill").foregroundStyle(.secondary)
        case "running": ProgressView().controlSize(.small)
        default: Image(systemName: "circle").foregroundStyle(.tertiary)
        }
    }
}
