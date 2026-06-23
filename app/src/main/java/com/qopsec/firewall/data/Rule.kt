package com.qopsec.firewall.data

import androidx.room.Entity
import androidx.room.PrimaryKey
import org.json.JSONArray
import org.json.JSONObject

/**
 * One firewall rule. A flow is matched against all enabled rules; the most *specific*
 * match wins (see [RuleRepository.decide]), so a per-app+host deny overrides a per-app
 * allow — e.g. "allow Facebook, but deny Facebook → graph.facebook.com".
 *
 * Nullable matchers act as wildcards: a null field matches anything. `scope` is advisory
 * (drives the UI label); matching is driven by which fields are set.
 *
 * Phase 2 slice 1 subset of the full report schema — reversibility columns (deleted_at,
 * journal, snapshots) arrive with the Trash/undo slice.
 */
@Entity(tableName = "rule")
data class Rule(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val scope: String,                  // "app" | "host" | "ip" | "global"
    val packageName: String? = null,
    val appUid: Int? = null,
    val appLabel: String? = null,       // for display
    val host: String? = null,           // exact or "*.example.com"
    val ip: String? = null,
    val port: Int? = null,
    val protocol: Int? = null,          // 6 TCP, 17 UDP, null = any
    val action: Int,                    // ACTION_ALLOW | ACTION_DENY
    val enabled: Boolean = true,
    val origin: String = "user",        // user | prompt | import | default
    val priority: Int = 0,
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis(),
    val deletedAt: Long? = null,        // null = active; else in Trash (soft-deleted)
) {
    companion object {
        const val ACTION_ALLOW = 0
        const val ACTION_DENY = 1
    }
}

// --- JSON (de)serialization for the undo journal (org.json, no extra deps) ---

fun Rule.toJson(): String = JSONObject().apply {
    put("id", id)
    put("scope", scope)
    putOpt("packageName", packageName)
    if (appUid != null) put("appUid", appUid)
    putOpt("appLabel", appLabel)
    putOpt("host", host)
    putOpt("ip", ip)
    if (port != null) put("port", port)
    if (protocol != null) put("protocol", protocol)
    put("action", action)
    put("enabled", enabled)
    put("origin", origin)
    put("priority", priority)
    put("createdAt", createdAt)
    put("updatedAt", updatedAt)
    if (deletedAt != null) put("deletedAt", deletedAt)
}.toString()

fun ruleFromJson(s: String): Rule {
    val o = JSONObject(s)
    return Rule(
        id = o.getLong("id"),
        scope = o.getString("scope"),
        packageName = o.optStringOrNull("packageName"),
        appUid = if (o.has("appUid")) o.getInt("appUid") else null,
        appLabel = o.optStringOrNull("appLabel"),
        host = o.optStringOrNull("host"),
        ip = o.optStringOrNull("ip"),
        port = if (o.has("port")) o.getInt("port") else null,
        protocol = if (o.has("protocol")) o.getInt("protocol") else null,
        action = o.getInt("action"),
        enabled = o.getBoolean("enabled"),
        origin = o.getString("origin"),
        priority = o.getInt("priority"),
        createdAt = o.getLong("createdAt"),
        updatedAt = o.getLong("updatedAt"),
        deletedAt = if (o.has("deletedAt")) o.getLong("deletedAt") else null,
    )
}

private fun JSONObject.optStringOrNull(key: String): String? =
    if (has(key) && !isNull(key)) getString(key) else null

/** Serialize a list of rules (for snapshots). */
fun rulesToJson(rules: List<Rule>): String {
    val arr = JSONArray()
    rules.forEach { arr.put(JSONObject(it.toJson())) }
    return arr.toString()
}

fun rulesFromJson(s: String): List<Rule> {
    val arr = JSONArray(s)
    return (0 until arr.length()).map { ruleFromJson(arr.getJSONObject(it).toString()) }
}
