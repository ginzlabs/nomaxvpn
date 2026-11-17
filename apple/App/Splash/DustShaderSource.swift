#if os(iOS)
/// The dust shaders, compiled at runtime by `DustRenderer` (off the main
/// thread in `prewarm()`), so building the app needs no Metal toolchain.
let dustShaderSource = """
    #include <metal_stdlib>
    using namespace metal;

    // Mirrors the Swift `DustUniforms`; keep field order and types in sync.
    struct DustUniforms {
        float2 viewportSize;
        float2 origin;
        float2 size;
        uint2 grid;
        float2 sweepDirection;
        float time;
        float sweepDuration;
        float jitter;
        float lifetime;
        float speed;
        float upwardForce;
    };

    struct DustVertexOut {
        float4 position [[position]];
        float2 uv;
        float alpha;
    };

    constant float fadeOutDuration = 0.3;

    static uint dustHash(uint value) {
        uint state = value * 747796405u + 2891336453u;
        uint word = ((state >> ((state >> 28u) + 4u)) ^ state) * 277803737u;
        return (word >> 22u) ^ word;
    }

    static float dustRandom(thread uint &state) {
        state = dustHash(state);
        return float(state) * (1.0 / 4294967296.0);
    }

    // One instance per grid cell. Positions are closed-form in time, so there is
    // no particle state: a frame is a single instanced draw.
    vertex DustVertexOut dustVertex(
        uint vid [[vertex_id]],
        uint iid [[instance_id]],
        constant DustUniforms &u [[buffer(0)]],
        texture2d<half> image [[texture(0)]]
    ) {
        constexpr sampler linear(coord::normalized, address::clamp_to_edge, filter::linear);

        float2 grid = float2(u.grid);
        float2 cellSize = 1.0 / grid;
        float2 cellMin = float2(iid % u.grid.x, iid / u.grid.x) * cellSize;
        float2 corner = float2(vid & 1, vid >> 1);

        DustVertexOut out;
        out.uv = cellMin + corner * cellSize;

        float2 inset = cellSize * 0.25;
        float2 cellMax = cellMin + cellSize - inset;
        half coverage = max(
            max(image.sample(linear, cellMin + inset, level(0)).a, image.sample(linear, float2(cellMax.x, cellMin.y + inset.y), level(0)).a),
            max(image.sample(linear, float2(cellMin.x + inset.x, cellMax.y), level(0)).a, image.sample(linear, cellMax, level(0)).a)
        );

        uint seed = dustHash(iid + 1u);
        float angle = dustRandom(seed) * (2.0 * M_PI_F);
        float speed = u.speed * (0.5 + 0.5 * dustRandom(seed));
        float lifetime = u.lifetime * (0.64 + 0.72 * dustRandom(seed));
        float jitter = u.jitter * dustRandom(seed);

        float front = saturate(dot(cellMin + cellSize * 0.5 - 0.5, u.sweepDirection) + 0.5);
        float t = max(0.0, u.time - front * u.sweepDuration - jitter);
        out.alpha = saturate((lifetime - t) / fadeOutDuration);

        if (coverage < 0.004h || out.alpha <= 0.0) {
            out.position = float4(-2.0, -2.0, 0.0, 1.0);
            out.alpha = 0.0;
            return out;
        }

        float2 velocity = float2(cos(angle), sin(angle)) * speed;
        float2 offset = velocity * t + float2(0.0, -0.5 * u.upwardForce * t * t);
        float2 point = u.origin + out.uv * u.size + offset;
        float2 ndc = point / u.viewportSize * 2.0 - 1.0;
        out.position = float4(ndc.x, -ndc.y, 0.0, 1.0);
        return out;
    }

    fragment half4 dustFragment(
        DustVertexOut in [[stage_in]],
        texture2d<half> image [[texture(0)]]
    ) {
        constexpr sampler linear(coord::normalized, address::clamp_to_edge, filter::linear);
        return image.sample(linear, in.uv) * half(in.alpha);
    }
    """
#endif
