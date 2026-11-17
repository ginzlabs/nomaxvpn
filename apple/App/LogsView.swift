import SwiftUI

/// The log, newest run first, with sharing and a run over every protocol.
struct LogsView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var confirmClear = false

    private var text: String { model.log.text(choice: model.protocolChoice) }

    var body: some View {
        NavigationStack {
            Group {
                if model.log.lines.isEmpty {
                    ContentUnavailableView("Nothing yet", systemImage: "list.bullet.rectangle",
                                           description: Text("Connection attempts and what the app does show up here."))
                } else {
                    List {
                        ForEach(model.log.sections) { s in
                            Section {
                                ForEach(s.lines.indices, id: \.self) { LogLineRow(line: s.lines[$0]) }
                            } header: {
                                Text("\(s.start.formatted(date: .abbreviated, time: .shortened)) · \(s.title)")
                                    .lineLimit(1)
                            }
                        }
                    }
                }
            }
            .navigationTitle("Logs")
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
                ToolbarItem(placement: .primaryAction) {
                    ShareLink(item: text)
                        .disabled(model.log.lines.isEmpty)
                }
                ToolbarItem(placement: .primaryAction) {
                    Menu {
                        Button("Copy", systemImage: "doc.on.doc") { copy() }
                        Button("Clear", systemImage: "trash", role: .destructive) { confirmClear = true }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                    }
                    .disabled(model.log.lines.isEmpty)
                    .accessibilityLabel("More")
                }
            }
            .safeAreaInset(edge: .bottom) {
                SendFoot(canSend: true) {
                    Button {
                        dismiss()
                        Task { await model.testAll() }
                    } label: {
                        Text("Test every protocol").bold()
                            .lineLimit(1).minimumScaleFactor(0.75)
                            .frame(maxWidth: .infinity, minHeight: 36)
                    }
                    .buttonStyle(.glassProminent)
                    .disabled(model.testing || model.enrollment == nil)
                }
            }
            .confirmationDialog("Clear the log?", isPresented: $confirmClear, titleVisibility: .visible) {
                Button("Clear", role: .destructive) { model.log.clear() }
            }
        }
        #if os(macOS)
        .frame(minWidth: 480, minHeight: 540)
        #endif
    }

    private func copy() {
        #if os(iOS)
        UIPasteboard.general.string = text
        #else
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        #endif
    }
}

/// The foot of Logs and the connection check: "Send to NoMax" beside the
/// screen's main button, and above them a line saying how sending went.
struct SendFoot<Main: View>: View {
    @Environment(AppModel.self) private var model
    var canSend: Bool
    @ViewBuilder var main: Main

    var body: some View {
        VStack(spacing: 8) {
            TimelineView(.periodic(from: .now, by: 1)) { t in
                let note = model.reports.note(at: t.date)
                if !note.isEmpty {
                    Text(note)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
            }
            HStack(spacing: 10) {
                Button {
                    Task { await model.sendReports() }
                } label: {
                    Text("Send to NoMax").bold()
                        .lineLimit(1).minimumScaleFactor(0.75)
                        .frame(maxWidth: .infinity, minHeight: 36)
                }
                .buttonStyle(.glass)
                .disabled(!canSend || model.reports.sending || model.enrollment == nil)
                main
            }
        }
        .animation(Brand.animation, value: model.reports.sending)
        .padding(.horizontal, 24)
        .padding(.bottom, 12)
    }
}

private struct LogLineRow: View {
    let line: LogLine

    private var color: Color {
        switch line.state {
        case "ok": .green
        case "fail": .red
        default: .secondary
        }
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(line.t, format: .dateTime.hour(.twoDigits(amPM: .omitted)).minute(.twoDigits).second(.twoDigits))
                .foregroundStyle(.secondary)
            Text(LogStore.mark(line.state))
                .foregroundStyle(color)
            if let proto = line.proto, !proto.isEmpty {
                Text("\(Text(LogStore.title(proto)).bold()) \(line.step)")
            } else {
                Text(line.step)
            }
        }
        .font(.caption.monospaced())
        .textSelection(.enabled)
    }
}
