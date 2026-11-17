import NetworkExtension
import SwiftUI

/// True while the launch splash still covers the app.
extension EnvironmentValues {
    @Entry var splashing = false
}

/// The brand mark, in silver.
/// "Version 1.0.0 (29)", quietly at the foot of the main screens.
struct VersionLabel: View {
    private var version: String {
        let info = Bundle.main.infoDictionary
        return "\(info?["CFBundleShortVersionString"] as? String ?? "?") (\(info?["CFBundleVersion"] as? String ?? "?"))"
    }

    var body: some View {
        Text("Version \(version)")
            .font(.caption2)
            .foregroundStyle(.tertiary)
            .textSelection(.enabled)
    }
}

struct BrandMark: View {
    var body: some View {
        Image("Mark")
            .resizable()
            .scaledToFit()
            .foregroundStyle(Brand.silver)
            .accessibilityHidden(true)
    }
}

enum Brand {
    static let silver = LinearGradient(
        colors: [Color(red: 0.957, green: 0.961, blue: 0.969), Color(red: 0.635, green: 0.655, blue: 0.686)],
        startPoint: .top, endPoint: .bottom)
    static let animation = Animation.smooth(duration: 0.35)
    static let cardWidth: CGFloat = 340
}

extension View {
    /// Replaces the view in place when `key` changes: the old one blurs out where it
    /// stands while the new one blurs in, so a change in width never moves anything.
    func swapped(on key: some Hashable, alignment: Alignment = .center) -> some View {
        ZStack(alignment: alignment) {
            id(key).transition(.blurReplace)
        }
    }
}

struct EnrollView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.splashing) private var splashing
    @State private var pin = ""
    @State private var shownError = ""
    @State private var shakes = 0
    @State private var showCheck = false
    @FocusState private var focused: Bool

    #if os(iOS)
    private let name = UIDevice.current.name
    #else
    private let name = Host.current().localizedName ?? "Mac"
    #endif

    private var complete: Bool { pin.count == PINBoxes.length }

    var body: some View {
        VStack(spacing: 0) {
            Spacer(minLength: 24).frame(maxHeight: 120)
            BrandMark().frame(height: 72)
            Text("Enter PIN")
                .font(.title3.weight(.semibold))
                .padding(.top, 28)
            ZStack {
                PINBoxes(pin: pin, active: focused && !model.busy ? pin.count : nil)
                    .modifier(Shake(travel: CGFloat(shakes)))
                TextField("", text: $pin)
                    #if os(iOS)
                    .keyboardType(.numberPad)
                    .textContentType(.oneTimeCode)
                    #endif
                    .focused($focused)
                    .font(.system(size: 40))
                    .foregroundStyle(.clear)
                    .tint(.clear)
                    .textFieldStyle(.plain)
                    .focusEffectDisabled()
                    .accessibilityIdentifier("pin")
                    .accessibilityLabel("PIN")
            }
            .contentShape(.rect)
            .onTapGesture { focused = true }
            .padding(.top, 24)
            Text(shownError)
                .font(.footnote)
                .foregroundStyle(.red)
                .multilineTextAlignment(.center)
                .lineLimit(2, reservesSpace: true)
                .opacity(model.error == nil ? 0 : 1)
                .padding(.top, 14)
            Button(action: join) {
                ZStack {
                    Text("Join").bold().opacity(model.busy ? 0 : 1)
                    ProgressView().opacity(model.busy ? 1 : 0)
                }
                .frame(maxWidth: .infinity, minHeight: 36)
            }
            .buttonStyle(.glassProminent)
            .disabled(!complete || model.busy)
            .padding(.top, 10)
            Button("Check connection") { showCheck = true }
                .font(.footnote)
                .buttonStyle(.borderless)
                .padding(.top, 18)
            if model.routes.count > 2 {
                @Bindable var model = model
                Menu {
                    Picker("Route", selection: $model.routeChoice) {
                        ForEach(model.routes) { Text($0.title).tag($0) }
                    }
                } label: {
                    Text("Route: \(model.routeChoice.title)")
                }
                .font(.footnote)
                .buttonStyle(.borderless)
                .disabled(model.busy)
                .padding(.top, 4)
            }
            Spacer()
            VersionLabel().padding(.bottom, 8)
        }
        .sheet(isPresented: $showCheck) { CheckView().environment(model) }
        .padding(.horizontal, 24)
        .frame(maxWidth: 420)
        #if os(iOS)
        .ignoresSafeArea(.keyboard)
        #endif
        .animation(Brand.animation, value: model.error)
        .animation(Brand.animation, value: model.busy)
        .animation(Brand.animation, value: complete)
        .onChange(of: pin) { _, v in
            let digits = String(v.filter(\.isWholeNumber).prefix(PINBoxes.length))
            if digits != v { pin = digits }
            if model.error != nil { model.error = nil }
        }
        .onChange(of: model.error) { _, e in
            guard let e else { return }
            shownError = e
            withAnimation(.linear(duration: 0.4)) { shakes += 1 }
        }
        .onAppear { if !splashing { focused = true }; usePending() }
        .onChange(of: splashing) { _, s in if !s { focused = true } }
        .onChange(of: model.pendingPIN) { _, _ in usePending() }
    }

    private func join() {
        guard complete, !model.busy else { return }
        Task { await model.enroll(pin: pin, deviceName: name) }
    }

    private func usePending() {
        guard let p = model.pendingPIN else { return }
        model.pendingPIN = nil
        pin = String(p.filter(\.isWholeNumber).prefix(PINBoxes.length))
        join()
    }
}

/// Six glass boxes, three, a dash, three; digits fade in as they're typed.
struct PINBoxes: View {
    static let length = 6
    let pin: String
    /// The box being typed into, while the field has focus.
    let active: Int?

    var body: some View {
        GlassEffectContainer(spacing: 8) {
            HStack(spacing: 8) {
                ForEach(0..<3) { box($0) }
                Capsule().fill(.secondary).frame(width: 12, height: 3).padding(.horizontal, 2)
                ForEach(3..<6) { box($0) }
            }
        }
        .animation(.smooth(duration: 0.25), value: pin)
        .animation(Brand.animation, value: active)
        .accessibilityHidden(true)
    }

    private func box(_ i: Int) -> some View {
        let digit = i < pin.count ? String(pin[pin.index(pin.startIndex, offsetBy: i)]) : nil
        return ZStack {
            if let digit {
                Text(digit)
                    .font(.system(size: 28, weight: .semibold, design: .rounded))
                    .monospacedDigit()
                    .transition(.opacity.combined(with: .scale(scale: 0.6)))
            }
        }
        .frame(width: 44, height: 56)
        .glassEffect(.regular.tint(i == active ? Color.accentColor.opacity(0.3) : nil).interactive(), in: .rect(cornerRadius: 14))
    }
}

/// A short horizontal shake; animate `travel` up by one per shake.
private struct Shake: GeometryEffect {
    var travel: CGFloat
    var animatableData: CGFloat {
        get { travel }
        set { travel = newValue }
    }

    func effectValue(size: CGSize) -> ProjectionTransform {
        ProjectionTransform(CGAffineTransform(translationX: 8 * sin(travel * .pi * 4), y: 0))
    }
}

struct HomeView: View {
    @Environment(AppModel.self) private var model
    @State private var confirmLeave = false
    @State private var showLogs = false
    @State private var showCheck = false
    @State private var shownError = ""
    /// Where the panel starts, for the run card that takes its place.
    @State private var panelTop: CGFloat = 0

    /// On iPhone Logs and More get a corner each, so either is easy to point someone to.
    private var moreMenuPlacement: ToolbarItemPlacement {
        #if os(iOS)
        .topBarLeading
        #else
        .primaryAction
        #endif
    }

    private var on: Bool { [.connected, .connecting, .reasserting].contains(model.status) }
    private var connected: Bool { model.status == .connected }
    /// Protocol and always-on can change only while the tunnel is off.
    private var settingsShown: Bool { model.status == .disconnected || model.status == .invalid }
    /// Auto and Test show their run in place of the panel, and
    /// a run where nothing worked stays up until it's closed.
    private var runShown: Bool {
        guard let run = model.run, run.kind != .single, !model.runDismissed else { return false }
        return run.failed || (!run.finished && [.connecting, .reasserting].contains(model.status))
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                Spacer(minLength: 12)
                Button {
                    Task { await model.toggle() }
                } label: {
                    Image(systemName: "power")
                        .font(.system(size: 64, weight: .semibold))
                        .foregroundStyle(on ? .white : .primary)
                        .symbolEffect(.pulse, isActive: model.status == .connecting || model.status == .reasserting)
                        .frame(width: 180, height: 180)
                        .glassEffect(.regular.tint(on ? .green : nil).interactive(), in: .circle)
                        .shadow(color: on ? .green.opacity(0.4) : .clear, radius: 24)
                }
                .buttonStyle(.plain)
                .sensoryFeedback(.impact, trigger: on)
                .accessibilityLabel(on ? "Disconnect" : "Connect")

                VStack(spacing: 4) {
                    Text(model.status.label)
                        .font(.title2.bold())
                        .swapped(on: model.status.label)
                    slot {
                        if connected, let p = model.activeProtocol {
                            Text("via \(p.title)").swapped(on: p)
                        }
                    }
                    .foregroundStyle(.secondary)
                    slot {
                        if connected, let since = model.connectedSince {
                            Text(since, style: .timer).transition(.blurReplace)
                        }
                    }
                    .monospacedDigit()
                    .foregroundStyle(.secondary)
                    HStack(spacing: 24) {
                        Label(bytes(model.stats?.rx ?? 0), systemImage: "arrow.down")
                        Label(bytes(model.stats?.tx ?? 0), systemImage: "arrow.up")
                    }
                    .font(.callout.monospacedDigit())
                    .foregroundStyle(.secondary)
                    .contentTransition(.numericText())
                    .opacity(connected && model.stats != nil ? 1 : 0)
                    .padding(.top, 4)
                }
                .padding(.top, 24)

                Text(shownError)
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
                    .lineLimit(2, reservesSpace: true)
                    .opacity(model.error == nil ? 0 : 1)
                    .padding(.horizontal)
                    .padding(.top, 8)

                // The unfolded panel keeps its space, so folding the settings moves nothing.
                HomePanel(settingsShown: true)
                    .hidden()
                    .overlay(alignment: .top) { HomePanel(settingsShown: settingsShown) }
                    .opacity(runShown ? 0 : 1)
                    .blur(radius: runShown ? 6 : 0)
                    .allowsHitTesting(!runShown)
                    .onGeometryChange(for: CGFloat.self) { $0.frame(in: .named("home")).minY } action: { panelTop = $0 }
                    .padding(.top, 8)

                // Equal space above and below, so the whole group sits in the middle.
                Spacer(minLength: 12)
                VersionLabel().padding(.bottom, 8)
            }
            .frame(maxWidth: .infinity)
            .coordinateSpace(.named("home"))
            .overlay(alignment: .top) {
                // The card starts where the panel does and takes up to the space below it.
                if runShown, let run = model.run {
                    VStack(spacing: 0) {
                        RunCard(run: run)
                        Spacer(minLength: 12)
                    }
                    .padding(.top, panelTop)
                    .transition(.blurReplace)
                }
            }
            .animation(Brand.animation, value: runShown)
            .animation(Brand.animation, value: model.status)
            .animation(Brand.animation, value: model.error)
            .animation(Brand.animation, value: model.activeProtocol)
            .animation(Brand.animation, value: model.stats?.rx)
            .animation(Brand.animation, value: model.ipResult)
            .animation(Brand.animation, value: model.checkingIP)
            .onChange(of: model.error) { _, e in if let e { shownError = e } }
            .toolbar {
                ToolbarItemGroup(placement: .primaryAction) {
                    // With the tunnel up, the check would test the tunnel's path.
                    Button { showCheck = true } label: {
                        Image(systemName: "stethoscope")
                    }
                    .accessibilityLabel("Check connection")
                    .disabled(on)
                    Button { showLogs = true } label: {
                        Image(systemName: "list.bullet.rectangle")
                    }
                    .accessibilityLabel("Logs")
                }
                ToolbarItem(placement: moreMenuPlacement) {
                    Menu {
                        if let host = model.enrollment?.profile.host {
                            Text(host)
                        }
                        Button("Remove this device", role: .destructive) { confirmLeave = true }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                    }
                    .accessibilityLabel("More")
                }
            }
            .confirmationDialog("Remove this device?", isPresented: $confirmLeave, titleVisibility: .visible) {
                Button("Remove", role: .destructive) { Task { await model.leave() } }
            } message: {
                Text("You'll need a new PIN to join again.")
            }
            .sheet(isPresented: $showLogs) {
                LogsView().environment(model)
            }
            .sheet(isPresented: $showCheck) {
                CheckView().environment(model)
            }
            .navigationTitle("NoMax")
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
        }
    }

    /// One line of text whose height stays reserved while its content comes and goes.
    private func slot(@ViewBuilder _ content: () -> some View) -> some View {
        ZStack {
            Text(" ").hidden()
            content()
        }
    }

    private func bytes(_ n: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: n, countStyle: .binary)
    }
}

/// Auto or Test as it runs: a row per protocol, each with its latest step.
/// The card's height stays put; the rows scroll to the one being tried.
struct RunCard: View {
    @Environment(AppModel.self) private var model
    let run: RunState

    private var progress: String {
        if run.failed { return "None worked" }
        return run.finished ? "Done" : "\(run.tried) of \(run.rows.count)"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                Text(run.kind == .test ? "Testing every protocol" : "Auto")
                    .font(.headline)
                Spacer()
                Text(progress)
                    .font(.subheadline.monospacedDigit())
                    .foregroundStyle(run.failed ? .red : .secondary)
                    .contentTransition(.numericText())
            }
            Text(run.headline)
                .font(.footnote)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .swapped(on: run.headline, alignment: .leading)
            ScrollViewReader { proxy in
                ScrollView {
                    VStack(spacing: 0) {
                        ForEach(run.rows) { RunRow(row: $0).id($0.id) }
                    }
                }
                .scrollIndicators(.hidden)
                .onChange(of: run.active) { _, active in
                    guard let active else { return }
                    withAnimation(Brand.animation) { proxy.scrollTo(active, anchor: .center) }
                }
            }
            if run.failed {
                HStack {
                    ShareLink(item: model.log.text(choice: model.protocolChoice)) {
                        Label("Share log", systemImage: "square.and.arrow.up")
                    }
                    .buttonStyle(.glassProminent)
                    Spacer()
                    Button("Close") { model.runDismissed = true }
                        .buttonStyle(.glass)
                }
                .padding(.top, 4)
                .transition(.blurReplace)
            }
        }
        .padding(18)
        .frame(width: Brand.cardWidth)
        .frame(maxHeight: 300)
        .glassEffect(.regular, in: .rect(cornerRadius: 22))
        .padding(.bottom, 12)
        .animation(Brand.animation, value: run)
    }
}

private struct RunRow: View {
    let row: RunState.Row

    var body: some View {
        HStack(spacing: 10) {
            icon
                .frame(width: 22, height: 22)
                .swapped(on: row.state)
            VStack(alignment: .leading, spacing: 1) {
                Text(row.title)
                    .font(.subheadline.weight(.semibold))
                Text(row.step.isEmpty ? " " : row.step)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .swapped(on: row.step, alignment: .leading)
            }
            Spacer(minLength: 0)
        }
        .padding(.vertical, 5)
        .opacity(row.state == .pending ? 0.45 : 1)
        .accessibilityElement(children: .combine)
    }

    @ViewBuilder private var icon: some View {
        switch row.state {
        case .pending: Image(systemName: "circle").foregroundStyle(.secondary)
        case .trying: ProgressView().controlSize(.small)
        case .ok: Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
        case .fail: Image(systemName: "xmark.circle.fill").foregroundStyle(.red)
        }
    }
}

/// What websites see, then protocol and always-on, on one glass card. The
/// settings fold away while the tunnel is on, since they change only while it's off.
struct HomePanel: View {
    @Environment(AppModel.self) private var model
    let settingsShown: Bool

    var body: some View {
        @Bindable var model = model
        VStack(spacing: 0) {
            IPCheckView(result: model.ipResult, checking: model.checkingIP) { model.checkIP() }
            if settingsShown {
                VStack(spacing: 0) {
                    Divider()
                    HStack {
                        Text("Protocol")
                        Spacer()
                        Picker("Protocol", selection: $model.protocolChoice) {
                            ForEach(model.protocols) { Text($0.title).tag($0) }
                        }
                        .pickerStyle(.menu)
                        .labelsHidden()
                    }
                    .frame(minHeight: 50)
                    if model.routes.count > 2 {
                        Divider()
                        HStack {
                            Text("Route")
                            Spacer()
                            Picker("Route", selection: $model.routeChoice) {
                                ForEach(model.routes) { Text($0.title).tag($0) }
                            }
                            .pickerStyle(.menu)
                            .labelsHidden()
                        }
                        .frame(minHeight: 50)
                    }
                    Divider()
                    Toggle("Always on", isOn: $model.alwaysOn)
                        .toggleStyle(.switch)
                        .frame(minHeight: 50)
                }
                .padding(.horizontal, 18)
                .transition(.opacity)
            }
        }
        .frame(width: Brand.cardWidth)
        .clipShape(.rect(cornerRadius: 22))
        .glassEffect(.regular, in: .rect(cornerRadius: 22))
    }
}

/// The IPv4 address and rough location websites see, at the top of the home
/// panel; tap to check again. The labels stay put and the values swap in place.
struct IPCheckView: View {
    let result: IPCheck.Result?
    let checking: Bool
    let refresh: () -> Void

    private enum Shown: Hashable {
        case found(IPCheck), unreachable, checking, idle
    }

    private var shown: Shown {
        switch result {
        case .found(let c): .found(c)
        case .unreachable: .unreachable
        case nil: checking ? .checking : .idle
        }
    }

    var body: some View {
        let shown = shown
        Button(action: refresh) {
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 6) {
                GridRow(alignment: .firstTextBaseline) {
                    Text("IP")
                        .font(.headline)
                        .foregroundStyle(.secondary)
                        .gridColumnAlignment(.center)
                    address(shown)
                        .font(.title2.weight(.semibold))
                        .lineLimit(1)
                        .minimumScaleFactor(0.6)
                        .swapped(on: shown, alignment: .leading)
                }
                GridRow(alignment: .firstTextBaseline) {
                    flag(shown)
                        .font(.headline)
                        .swapped(on: shown)
                    place(shown)
                        .font(.headline)
                        .lineLimit(1)
                        .minimumScaleFactor(0.7)
                        .swapped(on: shown, alignment: .leading)
                }
            }
            .frame(width: Brand.cardWidth - 36, alignment: .leading)
            .padding(.horizontal, 18)
            .padding(.vertical, 14)
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .opacity(checking && result != nil ? 0.55 : 1)
        .disabled(checking)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("ip")
        .accessibilityHint("Checks your IP address again")
    }

    @ViewBuilder private func address(_ s: Shown) -> some View {
        switch s {
        case .found(let c): Text(c.ip).monospaced()
        case .unreachable: Text("Unavailable").foregroundStyle(.secondary)
        case .checking: Text("000.000.000.000").monospaced().redacted(reason: .placeholder)
        case .idle: Text("Tap to check").foregroundStyle(.secondary)
        }
    }

    @ViewBuilder private func flag(_ s: Shown) -> some View {
        if case .found(let c) = s, let flag = c.flag {
            Text(flag)
        } else {
            Image(systemName: "globe").foregroundStyle(.secondary)
        }
    }

    @ViewBuilder private func place(_ s: Shown) -> some View {
        switch s {
        case .found(let c): Text(c.place)
        case .unreachable: Text("Tap to check again").foregroundStyle(.secondary)
        case .checking: Text("United Kingdom · LHR").redacted(reason: .placeholder)
        case .idle: Text("Location").foregroundStyle(.secondary)
        }
    }
}
