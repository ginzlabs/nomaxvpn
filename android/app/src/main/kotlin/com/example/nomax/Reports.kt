package com.example.nomax

import android.content.Context
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread
import kotlinx.coroutines.flow.MutableStateFlow
import nomaxcore.Nomaxcore
import org.json.JSONArray
import org.json.JSONObject

/**
 * Send: the log's lines and the connection checks the server doesn't have yet, in
 * one report (internal/panel/report.go). When the server can't be reached they
 * wait, and go by themselves once the tunnel is up or the app comes back.
 */
object Reports {
    private const val CHECKS_KEPT = 20
    private const val MAX_LINES = 5000
    private const val PREFS = "nomax"

    /** What the screens show about sending: the last outcome, and [at] when (ms). */
    data class Status(val sending: Boolean = false, val message: String = "", val at: Long = 0)

    val status = MutableStateFlow(Status())
    private val running = AtomicBoolean(false)

    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** A Send that couldn't reach the server yet. */
    fun pending(ctx: Context) = prefs(ctx).getBoolean("reportPending", false)

    data class Check(val t: Long, val text: String)

    private fun file(ctx: Context) = File(ctx.filesDir, "nomax-checks.jsonl")

    @Synchronized
    fun checks(ctx: Context): List<Check> = runCatching {
        file(ctx).readLines().mapNotNull { s ->
            runCatching { JSONObject(s).let { Check(it.getLong("t"), it.getString("text")) } }.getOrNull()
        }
    }.getOrDefault(emptyList())

    /** Keeps a finished connection check's report, unless it's the one kept last. */
    @Synchronized
    fun keepCheck(ctx: Context, text: String) {
        val cs = checks(ctx)
        if (text.isBlank() || cs.lastOrNull()?.text == text) return
        val kept = (cs + Check(System.currentTimeMillis(), text)).takeLast(CHECKS_KEPT)
        runCatching { file(ctx).writeText(kept.joinToString("") { JSONObject().put("t", it.t).put("text", it.text).toString() + "\n" }) }
    }

    fun sendIfPending(ctx: Context) {
        if (pending(ctx)) send(ctx, quiet = true)
    }

    /** Sends in the background. A [quiet] retry only speaks up once it got through. */
    fun send(ctx: Context, quiet: Boolean = false) {
        val e = Vault.load(ctx) ?: return
        if (!running.compareAndSet(false, true)) return
        status.value = if (quiet) status.value.copy(sending = true) else Status(true, "Sending…", System.currentTimeMillis())
        val app = ctx.applicationContext
        thread(name = "nomax-send") {
            var sent = false
            val message = try {
                sent = sendNow(app, e)
                if (sent) "Sent to NoMax. Thank you!" else "Everything's sent already."
            } catch (ex: ApiError) {
                prefs(app).edit().putBoolean("reportPending", false).apply()
                ex.message ?: "NoMax didn't take it."
            } catch (ex: Exception) {
                prefs(app).edit().putBoolean("reportPending", true).apply()
                "Can't reach NoMax right now. It's saved here and goes by itself once you're connected."
            } finally {
                running.set(false)
            }
            status.value = if (!quiet || sent) Status(false, message, System.currentTimeMillis()) else status.value.copy(sending = false)
        }
    }

    /** Whether there was something new to send; throws when it couldn't go. */
    private fun sendNow(ctx: Context, e: Enrollment): Boolean {
        CheckReport.parse(Nomaxcore.checkState())?.takeIf { it.done }?.let { keepCheck(ctx, Nomaxcore.checkText()) }
        val p = prefs(ctx)
        val since = p.getLong("reportSent", 0)
        RunLog.load(ctx)
        val lines = RunLog.lines.value.filter { it.t > since }.takeLast(MAX_LINES)
        val checks = checks(ctx).filter { it.t > since }
        if (lines.isEmpty() && checks.isEmpty()) {
            p.edit().putBoolean("reportPending", false).apply()
            return false
        }
        val body = JSONObject()
            .put("app", RunLog.appInfo())
            .put("lines", JSONArray(lines.map { JSONObject(it.toJson()) }))
            .put("checks", JSONArray(checks.map { JSONObject().put("t", it.t).put("text", it.text) }))
        e.api(ctx).report(e.deviceToken, body)
        val newest = maxOf(lines.maxOfOrNull { it.t } ?: 0, checks.maxOfOrNull { it.t } ?: 0)
        p.edit().putLong("reportSent", newest).putBoolean("reportPending", false).apply()
        return true
    }
}
