import SwiftUI

@main
struct NoMaxApp: App {
    @State private var model = AppModel()
    @State private var loaded = false
    @State private var splash = true
    @Environment(\.scenePhase) private var phase

    init() {
        #if os(iOS)
        DustRenderer.prewarm()
        #else
        NSApplication.shared.appearance = NSAppearance(named: .darkAqua)
        #endif
    }

    var body: some Scene {
        WindowGroup {
            ZStack {
                Group {
                    if model.enrollment == nil {
                        EnrollView().transition(.opacity)
                    } else {
                        HomeView().transition(.opacity)
                    }
                }
                .animation(.smooth(duration: 0.5), value: model.enrollment == nil)
                .environment(\.splashing, splash)
                if splash {
                    SplashView(ready: loaded) { splash = false }
                }
            }
            .environment(model)
            .preferredColorScheme(.dark)
            .onOpenURL { model.handle(url: $0) }
            .task {
                await model.load()
                loaded = true
            }
            .onChange(of: phase) { _, p in
                if p == .active { Task { await model.refreshProfile() } }
            }
        }
        #if os(macOS)
        .defaultSize(width: 420, height: 640)
        .windowResizability(.contentMinSize)
        #endif
    }
}
