package com.qopsec.firewall.data

import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

data class BlocklistSource(val id: String, val name: String, val url: String)

data class SourceInfo(val enabled: Boolean, val count: Int, val updatedAt: Long)

/**
 * Subscribable ad/tracker blocklists. Downloads each enabled list to a file, then rebuilds the
 * in-memory [BlockList] from the bundled seed plus all enabled files. Auto-updated by
 * [BlocklistUpdateWorker]. Metadata (enabled/count/updated) lives in SharedPreferences; the big
 * domain lists live as files (not Room) so the DB stays light.
 */
class BlocklistManager private constructor(private val app: Context) {

    val sources = listOf(
        BlocklistSource(
            "stevenblack", "StevenBlack hosts",
            "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        ),
        BlocklistSource(
            "peterlowe", "Peter Lowe's list",
            "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
        ),
        BlocklistSource(
            "adguard", "AdGuard DNS filter",
            "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
        ),
    )

    private val prefs = app.getSharedPreferences("qopsec_blocklists", Context.MODE_PRIVATE)
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private val _state = MutableStateFlow(readState())
    val state: StateFlow<Map<String, SourceInfo>> = _state.asStateFlow()

    init {
        // Load any cached subscription files into the matcher on startup.
        scope.launch { rebuild(); refreshState() }
    }

    fun isEnabled(id: String): Boolean = prefs.getBoolean("en_$id", false)

    /** Toggle a subscription: enabling downloads it; disabling removes its file. */
    fun setEnabled(id: String, on: Boolean) = scope.launch {
        prefs.edit().putBoolean("en_$id", on).apply()
        if (on) {
            sources.find { it.id == id }?.let { runCatching { download(it) } }
        } else {
            fileFor(id).delete()
            prefs.edit().remove("ct_$id").remove("up_$id").apply()
        }
        rebuild()        // merge into the matcher first…
        refreshState()   // …then emit so the UI's aggregate count reflects the rebuild
    }

    /** Manual "Update now". */
    fun updateNow() = scope.launch { updateAllInternal() }

    /** Called by the WorkManager job. */
    suspend fun updateAllBlocking() = updateAllInternal()

    private suspend fun updateAllInternal() {
        sources.filter { isEnabled(it.id) }.forEach { runCatching { download(it) } }
        rebuild()
        refreshState()
    }

    private fun download(s: BlocklistSource) {
        val domains = HashSet<String>(1 shl 16)
        val conn = (URL(s.url).openConnection() as HttpURLConnection).apply {
            connectTimeout = 15_000
            readTimeout = 60_000
            instanceFollowRedirects = true
        }
        try {
            conn.inputStream.bufferedReader().use { r ->
                r.forEachLine { line -> parseDomainLine(line)?.let(domains::add) }
            }
        } finally {
            conn.disconnect()
        }
        if (domains.isEmpty()) return // keep the previous file on a failed/empty fetch
        val f = fileFor(s.id)
        f.parentFile?.mkdirs()
        f.bufferedWriter().use { w -> domains.forEach { w.append(it); w.append('\n') } }
        prefs.edit().putInt("ct_${s.id}", domains.size).putLong("up_${s.id}", System.currentTimeMillis()).apply()
    }

    private fun enabledFiles(): List<File> =
        sources.filter { isEnabled(it.id) }.map { fileFor(it.id) }.filter { it.exists() }

    private fun rebuild() {
        BlockList.get(app).applyFiles(app, enabledFiles())
    }

    private fun fileFor(id: String) = File(app.filesDir, "blocklists/$id.txt")

    private fun readState(): Map<String, SourceInfo> = sources.associate {
        it.id to SourceInfo(
            enabled = prefs.getBoolean("en_${it.id}", false),
            count = prefs.getInt("ct_${it.id}", 0),
            updatedAt = prefs.getLong("up_${it.id}", 0L),
        )
    }

    private fun refreshState() {
        _state.value = readState()
    }

    companion object {
        @Volatile private var INSTANCE: BlocklistManager? = null

        fun get(context: Context): BlocklistManager =
            INSTANCE ?: synchronized(this) {
                INSTANCE ?: BlocklistManager(context.applicationContext).also { INSTANCE = it }
            }
    }
}
