package com.example.nomax

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.io.IOException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import nomaxcore.Nomaxcore
import org.json.JSONObject

/** The device's enrolment, the same shape as on iOS. The profile mirrors internal/profile.Profile. */
data class Enrollment(val profile: JSONObject, val deviceToken: String, val wgPrivateKey: String) {
    val host: String get() = profile.getString("host")

    /** The relays' addresses. */
    val relays: List<String>
        get() {
            val a = profile.optJSONArray("relays") ?: return emptyList()
            return (0 until a.length()).mapNotNull { a.optJSONObject(it)?.optString("address")?.takeIf(String::isNotEmpty) }
        }

    /** The device API on the chosen route. */
    fun api(ctx: Context) = Api(host, relays, Vault.route(ctx))

    fun offers(r: Route) = when (r) {
        Route.Auto, Route.Direct -> true
        Route.Relay -> relays.isNotEmpty()
        Route.Exit -> profile.has("exit")
    }

    /** The exit route has only the protocols Xray carries. */
    fun offers(p: Proto, r: Route) =
        !(r == Route.Exit && p in listOf(Proto.WireGuard, Proto.AmneziaWG, Proto.OpenVPN, Proto.OpenConnect, Proto.IKEv2)) && offers(p)

    fun offers(p: Proto) = when (p) {
        Proto.AmneziaWG -> profile.has("amneziawg")
        Proto.Hysteria2 -> profile.has("hysteria2")
        Proto.Hysteria2Obfs -> profile.optJSONObject("hysteria2")?.has("obfs") == true
        Proto.OpenVPN -> profile.optJSONObject("openvpn")?.has("cert") == true
        Proto.Mieru -> profile.has("mieru")
        Proto.TrustTunnel -> profile.has("trusttunnel")
        Proto.OpenConnect -> profile.has("openconnect")
        Proto.RealityMux -> (profile.optJSONObject("reality")?.optInt("muxPort") ?: 0) != 0
        Proto.AnyTLS -> profile.has("anytls")
        Proto.Cloudflare -> profile.has("cloudflare")
        Proto.IKEv2 -> profile.has("ikev2") && Build.VERSION.SDK_INT >= 30
        Proto.Auto, Proto.WireGuard, Proto.Reality -> true
    }

    fun toJson(): String = JSONObject()
        .put("profile", profile)
        .put("deviceToken", deviceToken)
        .put("wgPrivateKey", wgPrivateKey)
        .toString()

    companion object {
        fun parse(s: String) = JSONObject(s).let {
            Enrollment(it.getJSONObject("profile"), it.getString("deviceToken"), it.getString("wgPrivateKey"))
        }
    }
}

/** The protocol menu. After Auto, in the order Auto tries them (internal/profile.Protocols). */
enum class Proto(val id: String, val title: String) {
    Auto("auto", "Auto"),
    WireGuard("wireguard", "WireGuard"),
    AmneziaWG("amneziawg", "AmneziaWG"),
    Hysteria2("hysteria2", "Hysteria2"),
    Hysteria2Obfs("hysteria2obfs", "Hysteria2 Obfs"),
    OpenVPN("openvpn", "OpenVPN"),
    Mieru("mieru", "Mieru"),
    TrustTunnel("trusttunnel", "TrustTunnel"),
    OpenConnect("openconnect", "Cisco AnyConnect"),
    RealityMux("realitymux", "Reality Mux"),
    AnyTLS("anytls", "AnyTLS"),
    Reality("reality", "Reality"),
    Cloudflare("cloudflare", "Cloudflare"),

    /** Android's own client (Android 11+), not the Go core. */
    IKEv2("ikev2", "IKEv2");

    companion object {
        fun of(id: String?) = entries.firstOrNull { it.id == id } ?: Auto
    }
}

/** The way to the server: nomaxcore's Route constants. */
enum class Route(val id: String, val title: String) {
    Auto("auto", "Auto"),
    Direct("direct", "Direct"),
    Relay("relay", "Via relay"),
    Exit("exit", "Relay exit");

    companion object {
        fun of(id: String?) = entries.firstOrNull { it.id == id } ?: Auto

        /** The routes [e] has; before joining, [Relay] when the app was built with relays. */
        fun offered(e: Enrollment?) = entries.filter {
            if (e != null) e.offers(it) else it != Exit && (it != Relay || Nomaxcore.builtInRelays().isNotEmpty())
        }
    }
}

/** Keeps the enrolment encrypted with a key that never leaves the Android keystore. */
object Vault {
    private const val ALIAS = "nomax-enrollment"
    private const val PREFS = "nomax"

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build()
        )
        return gen.generateKey()
    }

    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun load(ctx: Context): Enrollment? = runCatching {
        val blob = Base64.decode(prefs(ctx).getString("enrollment", null) ?: return null, Base64.NO_WRAP)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, blob, 0, 12))
        Enrollment.parse(String(c.doFinal(blob, 12, blob.size - 12)))
    }.getOrNull()

    fun save(ctx: Context, e: Enrollment) {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key())
        val blob = c.iv + c.doFinal(e.toJson().toByteArray())
        prefs(ctx).edit().putString("enrollment", Base64.encodeToString(blob, Base64.NO_WRAP)).commit()
    }

    fun clear(ctx: Context) {
        prefs(ctx).edit().remove("enrollment").commit()
    }

    fun protocol(ctx: Context) = Proto.of(prefs(ctx).getString("protocol", null))

    fun setProtocol(ctx: Context, p: Proto) {
        prefs(ctx).edit().putString("protocol", p.id).apply()
    }

    fun route(ctx: Context) = Route.of(prefs(ctx).getString("route", null))

    fun setRoute(ctx: Context, r: Route) {
        prefs(ctx).edit().putString("route", r.id).apply()
    }

    /**
     * The order Auto learned ("worked,…|failed,…"), which the next Start takes;
     * older versions kept just the protocol that last got through.
     */
    fun lastGood(ctx: Context) = prefs(ctx).getString("lastGood", null).orEmpty()

    fun setLastGood(ctx: Context, order: String) {
        prefs(ctx).edit().putString("lastGood", order).apply()
    }
}

class ApiError(message: String, val unauthorized: Boolean = false) : Exception(message)

/**
 * The device API, through the server's address, a relay or the website's name behind
 * Cloudflare's proxy, whichever gets through (internal/apiclient). No [relays] means
 * the ones the app was built with. Blocking: call it off the main thread.
 */
class Api(private val host: String, private val relays: List<String> = emptyList(), private val route: Route = Route.Auto) {
    fun enroll(pin: String, deviceName: String, wgPublicKey: String): Pair<String, JSONObject> {
        val body = JSONObject().put("pin", pin).put("deviceName", deviceName).put("wgPublicKey", wgPublicKey)
        val r = call("POST", "enroll", body = body)
        return r.getString("deviceToken") to r.getJSONObject("profile")
    }

    fun profile(token: String): JSONObject = call("GET", "profile", token)

    fun deleteDevice(token: String) {
        runCatching { call("DELETE", "device", token) }
    }

    /** Cloudflare's trace page as the server sees it: what websites see while connected. */
    fun trace(token: String): String = request("GET", "trace", token)

    /** Sends log lines and connection checks; the server keeps each once and says how many were new. */
    fun report(token: String, body: JSONObject): Int = call("POST", "report", token, body).optInt("new")

    private fun call(method: String, path: String, token: String? = null, body: JSONObject? = null): JSONObject {
        val text = request(method, path, token, body)
        return if (text.isBlank()) JSONObject() else JSONObject(text)
    }

    private fun request(method: String, path: String, token: String? = null, body: JSONObject? = null): String {
        val via = if (route == Route.Relay || route == Route.Exit) "relay" else ""
        val answer = try {
            JSONObject(Nomaxcore.call(host, method, path, token.orEmpty(), body?.toString().orEmpty(), via, relays.joinToString(",")))
        } catch (ex: Exception) {
            throw IOException(ex.message ?: "Can't reach $host", ex)
        }
        val status = answer.getInt("status")
        val text = answer.optString("body")
        if (status !in 200..299) {
            val msg = runCatching { JSONObject(text).getString("error") }.getOrNull() ?: "Server error ($status)."
            throw ApiError(msg, unauthorized = status == 401)
        }
        return text
    }
}
