package com.qopsec.firewall.data

import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.launch

/**
 * Single source of truth for rules. Holds a live in-memory [snapshot] of the enabled
 * rules so the datapath can [decide] a verdict synchronously (the Rust core calls in on
 * every new flow and blocks for the answer — no DB I/O on that path).
 *
 * Matching = most-specific-match-wins. Each matching rule gets a specificity score; the
 * highest score decides. So a per-app+host deny (score 12) beats a per-app allow (score
 * 4): "allow Facebook, but block Facebook → graph.facebook.com".
 */
class RuleRepository private constructor(private val dao: RuleDao) {

    /** Verdict + the rule that produced it (null = fell through to the default). */
    data class Decision(val action: Int, val rule: Rule?)

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Hot-path snapshot of enabled rules, refreshed whenever the DB changes.
    @Volatile private var snapshot: List<Rule> = emptyList()

    /** All active rules (incl. disabled, excl. trashed) for the Rules screen. */
    val allRules: Flow<List<Rule>> = dao.allRules()

    /** Soft-deleted rules for the Trash screen. */
    val trashedRules: Flow<List<Rule>> = dao.trashedRules()

    /** Durable connection history (latest 1000), for the Connections view. */
    val connLog: Flow<List<ConnLog>> = dao.connLog()

    /**
     * Record/refresh a connection in the persistent history (one row per distinct flow).
     * Misattribution guard (a lost uid-lookup race labels flows root/unknown): never create a
     * root/unknown row for a destination already known under a real app, and when a destination
     * is recorded under a real app, drop any root/unknown rows for it — live, not just at start.
     */
    suspend fun recordConn(c: ConnLog) {
        if (c.appUid <= 0 && dao.hasAttributedSibling(c.proto, c.dstIp, c.dstPort, c.dstHost)) return
        if (dao.touchConn(c.flowKey, c.ts, c.dstHost, c.appLabel, c.ipVersion) == 0) {
            runCatching { dao.insertConn(c) }   // tolerate a unique-key race
        }
        if (c.appUid > 0) dao.healSiblingsOf(c.proto, c.dstIp, c.dstPort, c.dstHost)
    }

    fun clearConn() = scope.launch { dao.clearConn() }

    /** All recorded flows for one app (per-app connection export). */
    suspend fun connsForUid(uid: Int): List<ConnLog> = dao.connsForUidOnce(uid)

    /** Drop root/unknown history rows whose destination also exists under a real app. */
    suspend fun healMisattributedConns(): Int {
        dao.dropUidZeroTwins()
        dao.relabelUidZeroRows()
        return dao.healMisattributedConns()
    }

    // --- snapshots / restore points ---

    val snapshots: Flow<List<Snapshot>> = dao.snapshots()

    /** Capture the current active rules as a named restore point. */
    fun saveSnapshot(label: String) = scope.launch {
        val rules = dao.activeRulesOnce()
        dao.insertSnapshot(
            Snapshot(label = label, rulesJson = rulesToJson(rules), ruleCount = rules.size),
        )
    }

    /**
     * Replace the current active rules with the snapshot's. Takes a "Before restore" auto-snapshot
     * first (so the restore is reversible) and clears the undo journal (rule ids change wholesale).
     */
    fun restoreSnapshot(snapshot: Snapshot) = scope.launch {
        val current = dao.activeRulesOnce()
        dao.insertSnapshot(
            Snapshot(label = "Before restore", rulesJson = rulesToJson(current), ruleCount = current.size),
        )
        current.forEach { dao.delete(it) }
        rulesFromJson(snapshot.rulesJson).forEach { dao.insert(it.copy(id = 0, deletedAt = null)) }
        dao.clearJournal()
    }

    fun deleteSnapshot(snapshot: Snapshot) = scope.launch { dao.deleteSnapshot(snapshot) }

    init {
        scope.launch { dao.activeRules().collect { snapshot = it } }
    }

    /**
     * Decide a flow. `host` is the destination hostname if known (from the DNS cache).
     * `defaultAllow` is the posture when nothing matches (Phase 2 slice 1: allow).
     */
    fun decide(
        uid: Int,
        packageName: String?,
        protocol: Int,
        dstIp: String,
        host: String?,
        port: Int,
        defaultAllow: Boolean = true,
    ): Decision = decideIn(snapshot, uid, packageName, protocol, dstIp, host, port, defaultAllow)

    /** Same as [decide] but against an explicit rule list — used by the UI to show each row's
     *  CURRENT verdict live (so blocking an app flips all its rows at once). */
    fun decideIn(
        rules: List<Rule>,
        uid: Int,
        packageName: String?,
        protocol: Int,
        dstIp: String,
        host: String?,
        port: Int,
        defaultAllow: Boolean = true,
    ): Decision {
        var best: Rule? = null
        var bestScore = -1
        for (r in rules) {
            if (!r.enabled) continue
            val score = score(r, uid, packageName, protocol, dstIp, host, port) ?: continue
            if (score > bestScore || (score == bestScore && wins(r, best))) {
                best = r
                bestScore = score
            }
        }
        return best?.let { Decision(it.action, it) }
            ?: Decision(if (defaultAllow) Rule.ACTION_ALLOW else Rule.ACTION_DENY, null)
    }

    /** Specificity score if [r] matches the flow, else null (no match). */
    private fun score(
        r: Rule,
        uid: Int,
        packageName: String?,
        protocol: Int,
        dstIp: String,
        host: String?,
        port: Int,
    ): Int? {
        var s = 0

        val appMatcher = r.packageName != null || r.appUid != null
        if (appMatcher) {
            val byPkg = r.packageName != null && r.packageName == packageName
            val byUid = r.appUid != null && r.appUid == uid
            if (!byPkg && !byUid) return null
            s += 4
        }
        if (r.host != null) {
            if (host == null || !hostMatches(r.host, host)) return null
            s += 8
        }
        if (r.ip != null) {
            if (r.ip != dstIp) return null
            s += 8
        }
        if (r.port != null) {
            if (r.port != port) return null
            s += 2
        }
        if (r.protocol != null) {
            if (r.protocol != protocol) return null
            s += 1
        }
        return s // 0 = global (matches everything)
    }

    /** Tie-break at equal specificity: higher priority, then deny over allow, then newer. */
    private fun wins(candidate: Rule, current: Rule?): Boolean {
        if (current == null) return true
        if (candidate.priority != current.priority) return candidate.priority > current.priority
        if (candidate.action != current.action) return candidate.action == Rule.ACTION_DENY
        return candidate.updatedAt >= current.updatedAt
    }

    // --- mutations (UI / prompt) — each records undo-journal entries under one batchId ---

    /** Non-empty while there's something to undo (drives the Undo button). */
    val undoCount: Flow<Int> = dao.changeCount()

    fun add(rule: Rule) = scope.launch { jInsert(rule, newBatch()) }

    fun setEnabled(rule: Rule, enabled: Boolean) = scope.launch {
        jUpdate(rule, rule.copy(enabled = enabled, updatedAt = System.currentTimeMillis()), newBatch())
    }

    /** Move a rule to the Trash (soft-delete, restorable for the retention window). */
    fun delete(rule: Rule) = scope.launch { jSoftDelete(rule, newBatch()) }

    /** Bring a trashed rule back. */
    fun restore(rule: Rule) = scope.launch { jRestore(rule, newBatch()) }

    /** Permanently remove a trashed rule now (still journaled, so still undoable). */
    fun deleteForever(rule: Rule) = scope.launch { jHardDelete(rule, newBatch()) }

    /**
     * Secure wipe (irreversible): hard-delete ALL trashed rules and clear the undo journal, so
     * nothing in the Trash can be restored or undone. Active rules and connection history are
     * left intact (each has its own clear path).
     */
    fun secureWipe() = scope.launch {
        dao.purgeAllTrashed()
        dao.clearJournal()
        dao.clearSnapshots()
    }

    /**
     * Set the whole-app policy: clears any existing app-scope rules (no host/ip) for this app,
     * then inserts one with [action] (ALLOW/DENY). `action == null` = revert to default (no rule).
     * The clear + insert share one batch so a single Undo reverts the whole toggle.
     */
    fun setAppRule(uid: Int, packageName: String?, label: String?, action: Int?) = scope.launch {
        val batch = newBatch()
        dao.allOnce()
            .filter { it.deletedAt == null && it.host == null && it.ip == null && it.matchesApp(uid, packageName) }
            .forEach { jHardDelete(it, batch) }
        if (action != null) {
            jInsert(
                Rule(
                    scope = "app",
                    packageName = packageName,
                    appUid = uid.takeIf { it >= 0 },
                    appLabel = label,
                    action = action,
                    origin = "user",
                ),
                batch,
            )
        }
    }

    /**
     * Set the policy for one destination within an app. Uses a HOST rule when a hostname is
     * known (matches via the DNS cache), else an IP rule (matches the raw dst IP) — important
     * for flows with no resolved name (e.g. FCM to a bare IP). Clears the existing matching
     * rule first; `action == null` reverts to the app/default. priority 10 so it out-ranks a
     * broad app rule on ties (block app but allow one destination, or vice-versa).
     */
    fun setDestRule(
        uid: Int,
        packageName: String?,
        label: String?,
        host: String?,
        ip: String,
        action: Int?,
    ) = scope.launch {
        val batch = newBatch()
        dao.allOnce()
            .filter {
                it.deletedAt == null && it.matchesApp(uid, packageName) &&
                    if (host != null) it.host == host else (it.ip == ip && it.host == null)
            }
            .forEach { jHardDelete(it, batch) }
        if (action != null) {
            jInsert(
                Rule(
                    scope = if (host != null) "host" else "ip",
                    packageName = packageName,
                    appUid = uid.takeIf { it >= 0 },
                    appLabel = label,
                    host = host,
                    ip = if (host == null) ip else null,
                    action = action,
                    priority = 10,
                    origin = "user",
                ),
                batch,
            )
        }
    }

    /** One destination to bulk-block: app identity + the host (preferred) or raw IP. */
    data class DestTarget(
        val uid: Int,
        val packageName: String?,
        val label: String?,
        val host: String?,
        val ip: String,
    )

    /**
     * Bulk-block every destination in [targets] as per-app host/ip deny rules, all under ONE
     * batch so a single Undo (or Trash restore) reverts the whole action. Replaces any existing
     * matching dest rule for each target. Used by the Connections "Block all shown" action.
     */
    fun blockAllDest(targets: List<DestTarget>) = scope.launch {
        if (targets.isEmpty()) return@launch
        val batch = newBatch()
        val existing = dao.allOnce().filter { it.deletedAt == null }
        targets.forEach { t ->
            existing.filter {
                it.matchesApp(t.uid, t.packageName) &&
                    if (t.host != null) it.host == t.host else (it.ip == t.ip && it.host == null)
            }.forEach { jHardDelete(it, batch) }
            jInsert(
                Rule(
                    scope = if (t.host != null) "host" else "ip",
                    packageName = t.packageName,
                    appUid = t.uid.takeIf { it >= 0 },
                    appLabel = t.label,
                    host = t.host,
                    ip = if (t.host == null) t.ip else null,
                    action = Rule.ACTION_DENY,
                    priority = 10,
                    origin = "user",
                ),
                batch,
            )
        }
    }

    /** Revert the most recent user action (the whole batch), then drop its journal entries. */
    fun undoLast() = scope.launch {
        val latest = dao.latestChange() ?: return@launch
        // newest-first so a clear+insert batch undoes the insert before re-adding the deletes
        dao.changesInBatch(latest.batchId).forEach { c ->
            val before = c.before?.let { ruleFromJson(it) }
            if (before == null) {
                c.after?.let { dao.deleteById(ruleFromJson(it).id) }  // was a create
            } else {
                dao.upsert(before)                                    // restore prior state
            }
        }
        dao.deleteBatch(latest.batchId)
    }

    // --- journal helpers (perform DB op + record the change) ---

    private fun newBatch(): String = java.util.UUID.randomUUID().toString()

    private suspend fun jInsert(rule: Rule, batch: String) {
        val id = dao.insert(rule)
        dao.insertChange(RuleChange(op = "create", before = null, after = rule.copy(id = id).toJson(), batchId = batch))
    }

    private suspend fun jUpdate(before: Rule, after: Rule, batch: String) {
        dao.update(after)
        dao.insertChange(RuleChange(op = "update", before = before.toJson(), after = after.toJson(), batchId = batch))
    }

    private suspend fun jSoftDelete(rule: Rule, batch: String) {
        val ts = System.currentTimeMillis()
        dao.softDelete(rule.id, ts)
        dao.insertChange(RuleChange(op = "trash", before = rule.toJson(), after = rule.copy(deletedAt = ts).toJson(), batchId = batch))
    }

    private suspend fun jRestore(rule: Rule, batch: String) {
        dao.restore(rule.id)
        dao.insertChange(RuleChange(op = "restore", before = rule.toJson(), after = rule.copy(deletedAt = null).toJson(), batchId = batch))
    }

    private suspend fun jHardDelete(rule: Rule, batch: String) {
        dao.delete(rule)
        dao.insertChange(RuleChange(op = "delete", before = rule.toJson(), after = null, batchId = batch))
    }

    private fun Rule.matchesApp(uid: Int, packageName: String?): Boolean =
        (appUid != null && appUid == uid) || (packageName != null && this.packageName == packageName)

    companion object {
        @Volatile private var INSTANCE: RuleRepository? = null

        fun get(context: Context): RuleRepository =
            INSTANCE ?: synchronized(this) {
                INSTANCE ?: RuleRepository(AppDatabase.get(context).ruleDao()).also { INSTANCE = it }
            }

        /** host rule match: exact, or "*.example.com" matching the apex + any subdomain. */
        fun hostMatches(ruleHost: String, flowHost: String): Boolean {
            val r = ruleHost.lowercase()
            val f = flowHost.lowercase()
            return if (r.startsWith("*.")) {
                val base = r.substring(2)
                f == base || f.endsWith(".$base")
            } else {
                f == r
            }
        }
    }
}
