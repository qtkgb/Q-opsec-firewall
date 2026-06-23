package com.qopsec.firewall.data

import android.content.Context
import com.qopsec.firewall.R
import java.io.File

/**
 * In-memory ad/tracker domain blocklist — the bundled seed merged with any subscribed lists
 * ([BlocklistManager]) and the user's own custom-block domains ([UserDomains]). [isBlocked]
 * walks the label hierarchy so a listed domain also covers its subdomains (doubleclick.net →
 * ad.g.doubleclick.net). The on/off gate is at the call sites (Settings.adBlock), so this
 * stays a pure matcher.
 *
 * Two independent contributions are merged here so each can be rebuilt on its own:
 *  - [listed]    — bundled seed + subscription files (set by [applyFiles]).
 *  - [userBlock] — the user's custom-block domains (set by [applyUser]).
 * Their union is [blockSet]. A separate [allow] set holds the user's allowlist exceptions,
 * which override a block even when the domain is on a subscribed list (also un-sinkholes DNS).
 */
class BlockList private constructor(context: Context) {

    @Volatile private var listed: Set<String> = emptySet()     // seed + subscriptions
    @Volatile private var userBlock: Set<String> = emptySet()  // user's custom-block domains
    @Volatile private var allow: Set<String> = emptySet()      // user's allowlist exceptions
    @Volatile private var blockSet: Set<String> = emptySet()   // listed ∪ userBlock

    val size: Int get() = blockSet.size
    val allowSize: Int get() = allow.size

    init {
        listed = buildSet(context, emptyList()) // seed only until subscriptions are merged
        recombine()
    }

    /**
     * True if [host] (or a parent domain) is blocked. An allowlist match always wins, so a
     * user exception un-blocks the host even if it appears on a subscribed list.
     */
    fun isBlocked(host: String): Boolean {
        if (blockSet.isEmpty()) return false
        val h = host.lowercase().removeSuffix(".")
        if (matches(h, allow)) return false
        return matches(h, blockSet)
    }

    /** Label-walk match: a.b.c.com checks a.b.c.com, b.c.com, c.com (subdomain semantics). */
    private fun matches(host: String, set: Set<String>): Boolean {
        if (set.isEmpty()) return false
        var h = host
        while (h.isNotEmpty()) {
            if (h in set) return true
            val dot = h.indexOf('.')
            if (dot < 0) return false
            h = h.substring(dot + 1)
        }
        return false
    }

    /** Rebuild the listed set from the bundled seed plus the given subscription files. */
    fun applyFiles(context: Context, files: List<File>) {
        listed = buildSet(context, files)
        recombine()
    }

    /** Replace the user-maintained custom-block and allowlist-exception sets. */
    fun applyUser(block: Set<String>, allowList: Set<String>) {
        userBlock = block
        allow = allowList
        recombine()
    }

    private fun recombine() {
        blockSet = if (userBlock.isEmpty()) listed
        else HashSet<String>(listed.size + userBlock.size).apply { addAll(listed); addAll(userBlock) }
    }

    private fun buildSet(context: Context, files: List<File>): Set<String> {
        val set = HashSet<String>(1 shl 17)
        runCatching {
            context.resources.openRawResource(R.raw.blocklist_seed)
                .bufferedReader().forEachLine { parseDomainLine(it)?.let(set::add) }
        }
        files.forEach { f ->
            runCatching { f.bufferedReader().forEachLine { parseDomainLine(it)?.let(set::add) } }
        }
        return set
    }

    companion object {
        @Volatile private var INSTANCE: BlockList? = null

        fun get(context: Context): BlockList =
            INSTANCE ?: synchronized(this) {
                INSTANCE ?: BlockList(context.applicationContext).also { INSTANCE = it }
            }
    }
}

/** Accept "domain", "0.0.0.0 domain"/"127.0.0.1 domain" (hosts), and "||domain^" (ABP). */
internal fun parseDomainLine(raw: String): String? {
    var line = raw.trim()
    if (line.isEmpty() || line.startsWith("#") || line.startsWith("!")) return null
    if (line.startsWith("||")) line = line.removePrefix("||").substringBefore('^').substringBefore('/')
    if (line.contains(' ') || line.contains('\t')) line = line.split(Regex("\\s+")).last()
    line = line.lowercase().removePrefix("*.").trim('.')
    // drop localhost-ish hosts entries and anything that isn't a plain domain
    if (line == "localhost" || line == "localhost.localdomain" || line == "broadcasthost") return null
    return line.takeIf { it.isNotEmpty() && it.contains('.') && !it.contains('/') && !it.contains(':') }
}
