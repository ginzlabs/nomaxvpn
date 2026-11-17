import SwiftUI

/// The launch screen (black, SplashMark centred at its natural size) redrawn
/// over the app, then dissolved once the app is ready: the logo turns to dust
/// on iOS, everything fades with Reduce Motion, without Metal, or on the Mac.
struct SplashView: View {
    var ready: Bool
    var finished: () -> Void

    var body: some View {
        #if os(iOS)
        SplashDissolve(ready: ready, finished: finished)
            .ignoresSafeArea()
            .accessibilityHidden(true)
        #else
        SplashFade(ready: ready, finished: finished)
        #endif
    }
}

/// Seconds since the splash appeared.
private enum SplashTiming {
    /// Shortest time on screen, so a fast launch doesn't read as a flicker.
    static let minimumHold: TimeInterval = 0.15
    /// Leave anyway if the app takes this long to load.
    static let maximumHold: TimeInterval = 3
    /// From the start of the dissolve to the start of the background fade;
    /// the logo has broken up by then.
    static let backgroundFadeDelay: TimeInterval = 0.8
    static let backgroundFadeDuration: TimeInterval = 0.45
    static let crossFadeDuration: TimeInterval = 0.3
}

#if os(iOS)
private struct SplashDissolve: UIViewRepresentable {
    var ready: Bool
    var finished: () -> Void

    func makeUIView(context: Context) -> SplashUIView {
        let view = SplashUIView()
        view.finished = finished
        return view
    }

    func updateUIView(_ view: SplashUIView, context: Context) {
        if ready { view.markReady() }
    }
}

final class SplashUIView: UIView {
    var finished: (() -> Void)?
    private let image = UIImage(named: "SplashMark")
    private let imageView = UIImageView()
    private var dustView: DustEffectView?
    private var appearedAt: Date?
    private var ready = false
    private var dissolving = false

    init() {
        super.init(frame: .zero)
        backgroundColor = UIColor(named: "LaunchBackground") ?? .black
        imageView.image = image
        addSubview(imageView)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func layoutSubviews() {
        super.layoutSubviews()
        guard let size = image?.size else { return }
        let scale = traitCollection.displayScale
        imageView.frame = CGRect(
            x: ((bounds.width - size.width) / 2 * scale).rounded() / scale,
            y: ((bounds.height - size.height) / 2 * scale).rounded() / scale,
            width: size.width,
            height: size.height
        )
    }

    override func didMoveToWindow() {
        super.didMoveToWindow()
        guard window != nil, appearedAt == nil else { return }
        appearedAt = Date()
        if !UIAccessibility.isReduceMotionEnabled {
            Task { if await DustRenderer.ready() { self.prepareDust() } }
        }
        Task {
            try? await Task.sleep(for: .seconds(SplashTiming.maximumHold))
            await self.dissolve()
        }
        if ready { markReady() }
    }

    func markReady() {
        ready = true
        guard let appearedAt else { return }
        let wait = max(0, SplashTiming.minimumHold - Date().timeIntervalSince(appearedAt))
        Task {
            try? await Task.sleep(for: .seconds(wait))
            await self.dissolve()
        }
    }

    /// Adds the dust layer during the hold and draws an empty frame, so the
    /// dissolve's first frame doesn't pay for setting it up.
    @discardableResult
    private func prepareDust() -> DustEffectView {
        if let dustView { return dustView }
        layoutIfNeeded()
        let dustView = DustEffectView(frame: imageView.frame.insetBy(dx: -140, dy: -280).intersection(bounds))
        addSubview(dustView)
        dustView.warmUp()
        self.dustView = dustView
        return dustView
    }

    private func dissolve() async {
        guard !dissolving, let image else { return }
        dissolving = true
        isUserInteractionEnabled = false
        layoutIfNeeded()
        let dustAvailable = await DustRenderer.ready()
        if UIAccessibility.isReduceMotionEnabled || !dustAvailable {
            await animate(SplashTiming.crossFadeDuration) { self.alpha = 0 }
        } else {
            let dustView = prepareDust()
            let fade = Task {
                try? await Task.sleep(for: .seconds(SplashTiming.backgroundFadeDelay))
                await animate(SplashTiming.backgroundFadeDuration, curve: .curveEaseInOut) {
                    self.backgroundColor = .clear
                }
            }
            await dustView.disintegrate(image, in: convert(imageView.frame, to: dustView), hiding: imageView)
            if !imageView.isHidden {
                await animate(SplashTiming.crossFadeDuration) { self.imageView.alpha = 0 }
            }
            await fade.value
        }
        finished?()
    }

    private func animate(
        _ duration: TimeInterval,
        curve: UIView.AnimationOptions = .curveEaseOut,
        _ changes: @escaping @MainActor () -> Void
    ) async {
        await withCheckedContinuation { continuation in
            UIView.animate(withDuration: duration, delay: 0, options: [curve], animations: changes) { _ in
                continuation.resume()
            }
        }
    }
}
#else
private struct SplashFade: View {
    var ready: Bool
    var finished: () -> Void
    @State private var visible = true

    var body: some View {
        ZStack {
            Color("LaunchBackground")
            Image("SplashMark")
        }
        .ignoresSafeArea()
        .opacity(visible ? 1 : 0)
        .task(id: ready) {
            let hold = ready ? SplashTiming.minimumHold : SplashTiming.maximumHold
            try? await Task.sleep(for: .seconds(hold))
            if Task.isCancelled || !visible { return }
            withAnimation(.easeOut(duration: SplashTiming.crossFadeDuration)) { visible = false } completion: {
                finished()
            }
        }
        .accessibilityHidden(true)
    }
}
#endif
