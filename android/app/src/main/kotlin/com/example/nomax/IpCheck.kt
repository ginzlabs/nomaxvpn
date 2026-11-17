package com.example.nomax

import java.net.HttpURLConnection
import java.net.URL
import java.util.Locale

/** The IPv4 address websites see, from Cloudflare's trace page. */
data class IpCheck(val ip: String, val country: String, val colo: String) {
    /** "United Kingdom · LHR": the country, and the airport code of the Cloudflare data centre that answered. */
    val place: String
        get() {
            val name = runCatching { Locale.Builder().setRegion(country).build().displayCountry }.getOrNull()
            return listOf(name?.ifEmpty { null } ?: country, colo).filter { it.isNotEmpty() }.joinToString(" · ")
        }

    /** The country's flag emoji; null for Cloudflare's "XX" (unknown) and "T1" (Tor). */
    val flag: String?
        get() {
            val c = country.uppercase()
            if (c.length != 2 || c == "XX" || !c.all { it in 'A'..'Z' }) return null
            return c.map { String(Character.toChars(0x1F1E6 + (it - 'A'))) }.joinToString("")
        }

    sealed interface Result {
        data class Found(val check: IpCheck) : Result
        data object Unreachable : Result
    }

    companion object {
        private const val TRACE = "https://1.1.1.1/cdn-cgi/trace"

        /**
         * Asks Cloudflare directly, or the NoMax server when [via] is given. The app is
         * excluded from its own VPN, so while connected only the server sees what websites see.
         * Blocking: call it off the main thread.
         */
        fun run(via: Enrollment?): Result {
            val text = runCatching { if (via != null) Api(via.host, via.relays).trace(via.deviceToken) else fetch(TRACE) }.getOrNull()
                ?: return Result.Unreachable
            val fields = text.lineSequence()
                .mapNotNull { line -> line.split('=', limit = 2).takeIf { it.size == 2 }?.let { it[0] to it[1] } }
                .toMap()
            val ip = fields["ip"] ?: return Result.Unreachable
            return Result.Found(IpCheck(ip, fields["loc"].orEmpty(), fields["colo"].orEmpty()))
        }

        private fun fetch(url: String): String {
            val c = URL(url).openConnection() as HttpURLConnection
            try {
                c.connectTimeout = 6_000
                c.readTimeout = 6_000
                c.useCaches = false
                c.setRequestProperty("Connection", "close")
                check(c.responseCode == 200) { "trace: ${c.responseCode}" }
                return c.inputStream.bufferedReader().use { it.readText() }
            } finally {
                c.disconnect()
            }
        }
    }
}
