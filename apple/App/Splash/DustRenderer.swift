#if os(iOS)
import CoreGraphics
import Metal
import UIKit

/// Shared Metal state for every `DustEffectView`: device, queue and the one
/// render pipeline, compiled from `dustShaderSource`.
final class DustRenderer: Sendable {
    static let shared: DustRenderer? = DustRenderer()

    let device: any MTLDevice
    let queue: any MTLCommandQueue
    let pipeline: any MTLRenderPipelineState

    /// Whether this device can run the effect.
    static var isAvailable: Bool { shared != nil }

    private static let warmup = Task.detached(priority: .userInitiated) { shared != nil }

    /// Builds the pipeline off the main thread so the first frame doesn't stall.
    static func prewarm() {
        _ = warmup
    }

    /// Whether the effect can run, waiting for `prewarm` (starting it if needed)
    /// instead of blocking the caller on the shader compile like `isAvailable`.
    static func ready() async -> Bool {
        await warmup.value
    }

    private init?() {
        guard let device = MTLCreateSystemDefaultDevice(),
            let queue = device.makeCommandQueue(),
            let library = try? device.makeLibrary(source: dustShaderSource, options: nil),
            let vertex = library.makeFunction(name: "dustVertex"),
            let fragment = library.makeFunction(name: "dustFragment")
        else { return nil }

        let descriptor = MTLRenderPipelineDescriptor()
        descriptor.label = "Dust"
        descriptor.vertexFunction = vertex
        descriptor.fragmentFunction = fragment
        let attachment = descriptor.colorAttachments[0]!
        attachment.pixelFormat = .bgra8Unorm
        attachment.isBlendingEnabled = true
        attachment.sourceRGBBlendFactor = .one
        attachment.sourceAlphaBlendFactor = .one
        attachment.destinationRGBBlendFactor = .oneMinusSourceAlpha
        attachment.destinationAlphaBlendFactor = .oneMinusSourceAlpha
        guard let pipeline = try? device.makeRenderPipelineState(descriptor: descriptor) else { return nil }

        self.device = device
        self.queue = queue
        self.pipeline = pipeline
    }

    /// Rasterizes `image` at `scale` into a premultiplied BGRA texture whose
    /// first row is the image's top edge.
    func makeTexture(_ image: UIImage, size: CGSize, scale: CGFloat) -> (any MTLTexture)? {
        let width = max(1, Int((size.width * scale).rounded(.up)))
        let height = max(1, Int((size.height * scale).rounded(.up)))
        let bytesPerRow = width * 4
        var pixels = [UInt8](repeating: 0, count: bytesPerRow * height)
        let drawn: Bool = pixels.withUnsafeMutableBytes { buffer in
            guard
                let context = CGContext(
                    data: buffer.baseAddress,
                    width: width,
                    height: height,
                    bitsPerComponent: 8,
                    bytesPerRow: bytesPerRow,
                    space: CGColorSpace(name: CGColorSpace.sRGB)!,
                    bitmapInfo: CGImageAlphaInfo.premultipliedFirst.rawValue | CGBitmapInfo.byteOrder32Little.rawValue
                )
            else { return false }
            context.translateBy(x: 0, y: CGFloat(height))
            context.scaleBy(x: scale, y: -scale)
            UIGraphicsPushContext(context)
            image.draw(in: CGRect(origin: .zero, size: size))
            UIGraphicsPopContext()
            return true
        }
        guard drawn else { return nil }

        let descriptor = MTLTextureDescriptor.texture2DDescriptor(
            pixelFormat: .bgra8Unorm,
            width: width,
            height: height,
            mipmapped: false
        )
        descriptor.usage = .shaderRead
        descriptor.storageMode = .shared
        guard let texture = device.makeTexture(descriptor: descriptor) else { return nil }
        pixels.withUnsafeBytes { buffer in
            texture.replace(
                region: MTLRegionMake2D(0, 0, width, height),
                mipmapLevel: 0,
                withBytes: buffer.baseAddress!,
                bytesPerRow: bytesPerRow
            )
        }
        return texture
    }
}

/// Mirrors `DustUniforms` in `dustShaderSource`; keep field order and types in sync.
struct DustUniforms {
    var viewportSize: SIMD2<Float>
    var origin: SIMD2<Float>
    var size: SIMD2<Float>
    var grid: SIMD2<UInt32>
    var sweepDirection: SIMD2<Float>
    var time: Float
    var sweepDuration: Float
    var jitter: Float
    var lifetime: Float
    var speed: Float
    var upwardForce: Float
}
#endif
