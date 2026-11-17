package com.example.nomax

import android.content.Context
import android.os.Build
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlinx.coroutines.flow.MutableStateFlow
import nomaxcore.Nomaxcore
import org.json.JSONArray
import org.json.JSONObject

/**
 * One step of a connection run, from the Go core (core/events.go). A run starts
 * with "start" (proto auto, test or the protocol picked, and [order];
 * [reconnect] when the core began it to replace a tunnel that stopped carrying
 * traffic), each protocol goes "trying" then "ok" or "fail", and "done" names
 * the protocol that connected, or none. Steps never contain keys or passwords.
 */
data class RunEvent(
    val seq: Long, val t: Long, val run: Long, val proto: String, val state: String, val step: String, val order: List<String>,
    val reconnect: Boolean = false,
) {
    companion object {
        fun parse(o: JSONObject) = RunEvent(
            o.getLong("seq"), o.getLong("t"), o.getLong("run"), o.optString("proto"), o.optString("state"), o.optString("step"),
            o.optJSONArray("order")?.let { a -> List(a.length()) { a.getString(it) } } ?: emptyList(),
            o.optBoolean("reconnect"),
        )
    }
}

/** One line of the log: a step from the tunnel, or something the app did (run 0). */
data class LogLine(val t: Long, val run: Long, val proto: String, val state: String, val step: String) {
    fun toJson(): String = JSONObject().put("t", t).put("run", run).put("proto", proto).put("state", state).put("step", step).toString()

    companion object {
        fun of(e: RunEvent) = LogLine(e.t, e.run, e.proto, e.state, e.step)

        fun parse(s: String) = runCatching {
            JSONObject(s).let { LogLine(it.getLong("t"), it.optLong("run"), it.optString("proto"), it.optString("state"), it.optString("step")) }
        }.getOrNull()
    }
}

/** An Auto or Test run as the run card shows it: a row per protocol. */
data class RunState(
    val id: Long,
    val kind: Kind,
    val rows: List<Row>,
    val headline: String,
    val finished: Boolean = false,
    /** The protocol that connected, once the run is done. */
    val winner: String? = null,
) {
    enum class Kind { Auto, Test, Single }
    enum class RowState { Pending, Trying, Ok, Fail }

    data class Row(val proto: String, val state: RowState = RowState.Pending, val step: String = "") {
        val title get() = RunLog.title(proto)
    }

    val failed get() = finished && winner == null
    val active get() = rows.indexOfLast { it.state == RowState.Trying }.takeIf { it >= 0 }
    val tried get() = rows.count { it.state != RowState.Pending }

    fun apply(e: RunEvent): RunState {
        if (e.run != id) return this
        val i = rows.indexOfFirst { it.proto == e.proto }
        return when (e.state) {
            "trying", "ok", "fail" -> if (i < 0) this else {
                val s = when (e.state) {
                    "ok" -> RowState.Ok
                    "fail" -> RowState.Fail
                    else -> RowState.Trying
                }
                copy(rows = rows.toMutableList().also { it[i] = it[i].copy(state = s, step = e.step) })
            }
            "done" -> copy(finished = true, winner = e.proto.ifEmpty { null }, headline = e.step)
            "info" -> when {
                i >= 0 -> copy(rows = rows.toMutableList().also { it[i] = it[i].copy(step = e.step) })
                !finished -> copy(headline = e.step)
                else -> this
            }
            else -> this
        }
    }

    companion object {
        fun start(e: RunEvent): RunState? {
            if (e.state != "start") return null
            val kind = when (e.proto) {
                Proto.Auto.id -> Kind.Auto
                Tunnel.TEST -> Kind.Test
                else -> Kind.Single
            }
            return RunState(e.run, kind, e.order.map { Row(it) }, e.step)
        }
    }
}

/**
 * The log, kept as JSON lines in the app's files and capped at [CAP] lines. The
 * Go core runs in this process, so a new process starts with a new core and
 * every step it has is new.
 */
object RunLog {
    private const val CAP = 2000

    val lines = MutableStateFlow<List<LogLine>>(emptyList())
    /** The latest run, from the tunnel's steps. */
    val run = MutableStateFlow<RunState?>(null)
    /** Hides the run card until the next run starts. */
    val dismissed = MutableStateFlow(false)

    private var lastSeq = 0L
    private var file: File? = null

    @Synchronized
    fun load(ctx: Context): File = file ?: File(ctx.filesDir, "nomax-log.jsonl").also { f ->
        file = f
        lines.value = runCatching { f.readLines().mapNotNull(LogLine::parse) }.getOrDefault(emptyList())
    }

    /** Takes the core's new steps into the log and the run card. */
    @Synchronized
    fun poll(ctx: Context) {
        val a = runCatching { JSONArray(Nomaxcore.events(lastSeq)) }.getOrNull() ?: return
        if (a.length() == 0) return
        load(ctx)
        val events = List(a.length()) { RunEvent.parse(a.getJSONObject(it)) }.filter { it.seq > lastSeq }.sortedBy { it.seq }
        if (events.isEmpty()) return
        lastSeq = events.last().seq
        var r = run.value
        for (e in events) {
            val started = RunState.start(e)
            if (started != null) {
                r = started
                dismissed.value = false
            } else {
                r = r?.apply(e)
            }
            Tunnel.follow(ctx, e, r)
        }
        run.value = r
        append(events.map(LogLine::of))
    }

    @Synchronized
    fun app(ctx: Context, step: String) {
        load(ctx)
        append(listOf(LogLine(System.currentTimeMillis(), 0, "", "info", step)))
    }

    @Synchronized
    fun clear(ctx: Context) {
        load(ctx).delete()
        lines.value = emptyList()
    }

    private fun append(new: List<LogLine>) {
        val f = file ?: return
        val all = lines.value + new
        if (all.size > CAP + CAP / 4) {
            val kept = all.takeLast(CAP)
            lines.value = kept
            runCatching { f.writeText(kept.joinToString("") { it.toJson() + "\n" }) }
        } else {
            lines.value = all
            runCatching { f.appendText(new.joinToString("") { it.toJson() + "\n" }) }
        }
    }

    data class Section(val run: Long, val lines: List<LogLine>) {
        val title get() = if (run == 0L) "App" else lines.firstOrNull { it.state == "start" }?.step ?: "Tunnel"
        val start get() = lines.firstOrNull()?.t ?: 0L
    }

    /**
     * A section per run, newest first. The tunnel's steps for a run stay together
     * even when the app logged something meanwhile; the app's lines get sections of their own.
     */
    fun sections(lines: List<LogLine>): List<Section> {
        val groups = mutableListOf<Pair<Long, MutableList<LogLine>>>()
        val byRun = mutableMapOf<Long, MutableList<LogLine>>()
        for (l in lines) {
            val open = if (l.run != 0L) byRun[l.run] else groups.lastOrNull()?.takeIf { it.first == 0L }?.second
            if (open != null) {
                open += l
            } else {
                val g = mutableListOf(l)
                if (l.run != 0L) byRun[l.run] = g
                groups += l.run to g
            }
        }
        return groups.map { Section(it.first, it.second) }.reversed()
    }

    /** "NoMax 1.0 (33) · Pixel 9, Android 16": the app and device, for what gets shared. */
    fun appInfo() = "NoMax ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE}) · ${Build.MODEL}, Android ${Build.VERSION.RELEASE}"

    /** The log as plain text, newest run first, ready to paste into a chat. */
    fun text(choice: Proto): String {
        val day = SimpleDateFormat("d MMM HH:mm", Locale.getDefault())
        val time = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
        val b = StringBuilder("${appInfo()} · protocol ${choice.title}\n")
        for (s in sections(lines.value)) {
            b.append("\n— ${day.format(Date(s.start))} · ${s.title}\n")
            for (l in s.lines) {
                val name = if (l.proto.isEmpty()) "" else "${title(l.proto)}: "
                b.append("${time.format(Date(l.t))} ${mark(l.state)} $name${l.step}\n")
            }
        }
        return b.toString()
    }

    fun title(proto: String) = if (proto == Tunnel.TEST) "Test" else Proto.entries.firstOrNull { it.id == proto }?.title ?: proto

    fun mark(state: String) = when (state) {
        "ok" -> "✓"
        "fail" -> "✗"
        "trying" -> "…"
        "start" -> "▶"
        "done" -> "■"
        else -> "·"
    }
}
