#if os(iOS)
import Metal
import QuartzCore
import UIKit

/// A transparent overlay that turns images into dust. Place it above the
/// views to disintegrate and remove it when `disintegrate` returns.
@MainActor
final class DustEffectView: UIView {
    private struct Effect {
        let texture: any MTLTexture
        let rect: CGRect
        let configuration: DustConfiguration
        let instanceCount: Int
        let grid: SIMD2<UInt32>
        var elapsed: TimeInterval = 0
        let completion: CheckedContinuation<Void, Never>
    }

    /// Longest step a frame may advance, so a hitch or a trip to the
    /// background doesn't skip the animation.
    private static let maximumStep: TimeInterval = 1.0 / 30.0

    private var effects: [Effect] = []
    private var displayLink: CADisplayLink?
    private var lastTimestamp: CFTimeInterval?

    override class var layerClass: AnyClass { CAMetalLayer.self }

    private var metalLayer: CAMetalLayer { unsafeDowncast(layer, to: CAMetalLayer.self) }

    override init(frame: CGRect) {
        super.init(frame: frame)
        isOpaque = false
        backgroundColor = .clear
        isUserInteractionEnabled = false
        let metalLayer = self.metalLayer
        metalLayer.device = DustRenderer.shared?.device
        metalLayer.pixelFormat = .bgra8Unorm
        metalLayer.colorspace = CGColorSpace(name: CGColorSpace.sRGB)
        metalLayer.framebufferOnly = true
        metalLayer.isOpaque = false
        metalLayer.maximumDrawableCount = 3
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func layoutSubviews() {
        super.layoutSubviews()
        let scale = window?.screen.scale ?? traitCollection.displayScale
        contentScaleFactor = scale
        metalLayer.drawableSize = CGSize(width: bounds.width * scale, height: bounds.height * scale)
    }

    override func didMoveToWindow() {
        super.didMoveToWindow()
        if window == nil { finishAll() }
    }

    /// Draws one empty frame, so the drawables and the GPU pipeline are set up
    /// before the first real frame has to land on time.
    func warmUp() {
        guard window != nil else { return }
        layoutIfNeeded()
        render(synchronizedWithTransaction: false)
    }

    /// Disintegrates `image`, drawn at `rect` in this view's coordinates, and
    /// hides `source` in the same transaction as the first dust frame, so the
    /// swap is seamless. Returns when the dust is gone. Returns at once, leaving
    /// `source` visible, if the effect can't run.
    func disintegrate(
        _ image: UIImage,
        in rect: CGRect,
        hiding source: UIView? = nil,
        configuration: DustConfiguration = DustConfiguration()
    ) async {
        guard let renderer = DustRenderer.shared, window != nil, !rect.isEmpty else { return }
        layoutIfNeeded()
        guard let texture = renderer.makeTexture(image, size: rect.size, scale: contentScaleFactor) else { return }
        let grid = configuration.grid(for: rect.size)

        await withCheckedContinuation { continuation in
            effects.append(
                Effect(
                    texture: texture,
                    rect: rect,
                    configuration: configuration,
                    instanceCount: grid.columns * grid.rows,
                    grid: SIMD2(UInt32(grid.columns), UInt32(grid.rows)),
                    completion: continuation
                )
            )
            render(synchronizedWithTransaction: true)
            source?.isHidden = true
            startDisplayLink()
        }
    }

    private func startDisplayLink() {
        guard displayLink == nil else { return }
        let link = CADisplayLink(target: self, selector: #selector(step(_:)))
        link.preferredFrameRateRange = CAFrameRateRange(minimum: 60, maximum: 120, preferred: 120)
        link.add(to: .main, forMode: .common)
        displayLink = link
        lastTimestamp = nil
    }

    private func stopDisplayLink() {
        displayLink?.invalidate()
        displayLink = nil
        lastTimestamp = nil
    }

    @objc private func step(_ link: CADisplayLink) {
        let delta = lastTimestamp.map { min(link.timestamp - $0, Self.maximumStep) } ?? 0
        lastTimestamp = link.timestamp

        var finished: [CheckedContinuation<Void, Never>] = []
        effects = effects.compactMap { effect in
            var effect = effect
            effect.elapsed += delta
            if effect.elapsed >= effect.configuration.totalDuration {
                finished.append(effect.completion)
                return nil
            }
            return effect
        }
        render(synchronizedWithTransaction: false)
        if effects.isEmpty { stopDisplayLink() }
        for completion in finished { completion.resume() }
    }

    private func finishAll() {
        stopDisplayLink()
        let pending = effects
        effects = []
        for effect in pending { effect.completion.resume() }
    }

    private func render(synchronizedWithTransaction: Bool) {
        guard let renderer = DustRenderer.shared, !bounds.isEmpty else { return }
        metalLayer.presentsWithTransaction = synchronizedWithTransaction
        guard let drawable = metalLayer.nextDrawable(),
            let commandBuffer = renderer.queue.makeCommandBuffer()
        else { return }

        let pass = MTLRenderPassDescriptor()
        pass.colorAttachments[0].texture = drawable.texture
        pass.colorAttachments[0].loadAction = .clear
        pass.colorAttachments[0].storeAction = .store
        pass.colorAttachments[0].clearColor = MTLClearColor(red: 0, green: 0, blue: 0, alpha: 0)
        guard let encoder = commandBuffer.makeRenderCommandEncoder(descriptor: pass) else { return }
        encoder.setRenderPipelineState(renderer.pipeline)

        let viewport = SIMD2(Float(bounds.width), Float(bounds.height))
        for effect in effects {
            let configuration = effect.configuration
            var uniforms = DustUniforms(
                viewportSize: viewport,
                origin: SIMD2(Float(effect.rect.minX), Float(effect.rect.minY)),
                size: SIMD2(Float(effect.rect.width), Float(effect.rect.height)),
                grid: effect.grid,
                sweepDirection: configuration.sweep.direction,
                time: Float(effect.elapsed),
                sweepDuration: Float(configuration.sweepDuration),
                jitter: Float(configuration.jitter),
                lifetime: Float(configuration.lifetime),
                speed: Float(configuration.speed),
                upwardForce: Float(configuration.upwardForce)
            )
            encoder.setVertexBytes(&uniforms, length: MemoryLayout<DustUniforms>.stride, index: 0)
            encoder.setVertexTexture(effect.texture, index: 0)
            encoder.setFragmentTexture(effect.texture, index: 0)
            encoder.drawPrimitives(type: .triangleStrip, vertexStart: 0, vertexCount: 4, instanceCount: effect.instanceCount)
        }
        encoder.endEncoding()

        if synchronizedWithTransaction {
            commandBuffer.commit()
            commandBuffer.waitUntilScheduled()
            drawable.present()
        } else {
            commandBuffer.present(drawable)
            commandBuffer.commit()
        }
    }
}
#endif
