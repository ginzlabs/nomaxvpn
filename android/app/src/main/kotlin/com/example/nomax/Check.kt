package com.example.nomax

import org.json.JSONObject

/** A connection check as the core reports it (Nomaxcore.checkState). */
data class CheckReport(val done: Boolean, val verdict: String, val steps: List<Step>) {
    data class Step(val id: String, val group: String, val title: String, val state: String, val detail: String)

    /** The steps by group, in the order the check lists them. */
    val groups: List<Pair<String, List<Step>>>
        get() = steps.fold(mutableListOf<Pair<String, MutableList<Step>>>()) { out, s ->
            if (out.lastOrNull()?.first == s.group) out.last().second += s else out += s.group to mutableListOf(s)
            out
        }

    companion object {
        fun parse(json: String): CheckReport? = runCatching {
            val o = JSONObject(json)
            val a = o.optJSONArray("steps") ?: return null
            CheckReport(
                done = o.optBoolean("done"),
                verdict = o.optString("verdict"),
                steps = (0 until a.length()).map { i ->
                    val s = a.getJSONObject(i)
                    Step(s.getString("id"), s.getString("group"), s.getString("title"), s.getString("state"), s.optString("detail"))
                },
            )
        }.getOrNull()
    }
}
