#if os(iOS)
import CoreGraphics
import Foundation

/// Tuning for one disintegration. Times are in seconds, distances in points.
struct DustConfiguration: Sendable, Equatable {
    /// The edge the release front starts from.
    enum Sweep: Sendable, Equatable {
        case leftToRight
        case rightToLeft
        case topToBottom
        case bottomToTop

        var direction: SIMD2<Float> {
            switch self {
            case .leftToRight: SIMD2(1, 0)
            case .rightToLeft: SIMD2(-1, 0)
            case .topToBottom: SIMD2(0, 1)
            case .bottomToTop: SIMD2(0, -1)
            }
        }
    }

    /// Edge length of one particle. Particle count is area / particleSize².
    var particleSize: CGFloat
    /// Time for the release front to cross the image.
    var sweepDuration: TimeInterval
    /// Random extra delay per particle, so the front isn't a hard line.
    var jitter: TimeInterval
    /// Mean particle lifetime after release; each particle gets 0.64x to 1.36x.
    var lifetime: TimeInterval
    /// Maximum initial speed; each particle gets 0.5x to 1x in a random direction.
    var speed: CGFloat
    /// Constant upward acceleration.
    var upwardForce: CGFloat
    var sweep: Sweep

    init(
        particleSize: CGFloat = 1,
        sweepDuration: TimeInterval = 0.5,
        jitter: TimeInterval = 0.08,
        lifetime: TimeInterval = 0.55,
        speed: CGFloat = 168,
        upwardForce: CGFloat = 480,
        sweep: Sweep = .leftToRight
    ) {
        self.particleSize = particleSize
        self.sweepDuration = sweepDuration
        self.jitter = jitter
        self.lifetime = lifetime
        self.speed = speed
        self.upwardForce = upwardForce
        self.sweep = sweep
    }

    /// When the last particle has faded out.
    var totalDuration: TimeInterval {
        sweepDuration + jitter + lifetime * 1.36
    }

    /// Particle columns and rows for an image of `size` points.
    func grid(for size: CGSize) -> (columns: Int, rows: Int) {
        let edge = max(particleSize, 0.25)
        return (
            max(1, Int((size.width / edge).rounded(.up))),
            max(1, Int((size.height / edge).rounded(.up)))
        )
    }
}
#endif
