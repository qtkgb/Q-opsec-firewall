package com.qopsec.firewall.data

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * User-maintained ad-block domain lists, persisted in SharedPreferences and pushed into the
 * in-memory [BlockList]:
 *  - [block] — custom domains to block (on top of the subscribed lists).
 *  - [allow] — allowlist exceptions that override a block (also un-sinkholes their DNS).
 *
 * Entries are normalised through [parseDomainLine] so "||ads.example.com^", "0.0.0.0 ads.x"
 * and "ads.x" all store as "ads.example.com". These lists are small (hand-entered) so a
 * StringSet in prefs is plenty — the big subscribed lists stay in files ([BlocklistManager]).
 */
class UserDomains private constructor(private val app: Context) {

    private val prefs = app.getSharedPreferences("qopsec_userdomains", Context.MODE_PRIVATE)

    private val _block = MutableStateFlow(load(KEY_BLOCK))
    val block: StateFlow<Set<String>> = _block.asStateFlow()

    private val _allow = MutableStateFlow(load(KEY_ALLOW))
    val allow: StateFlow<Set<String>> = _allow.asStateFlow()

    init {
        push() // make sure the matcher reflects stored lists on startup
    }

    /** Add a domain to the custom-block list. Returns the normalised value, or null if invalid. */
    fun addBlock(input: String): String? = mutate(KEY_BLOCK, _block, input, add = true)

    fun removeBlock(domain: String) = mutate(KEY_BLOCK, _block, domain, add = false)

    /** Add a domain to the allowlist exceptions. Returns the normalised value, or null if invalid. */
    fun addAllow(input: String): String? = mutate(KEY_ALLOW, _allow, input, add = true)

    fun removeAllow(domain: String) = mutate(KEY_ALLOW, _allow, domain, add = false)

    private fun mutate(
        key: String,
        flow: MutableStateFlow<Set<String>>,
        input: String,
        add: Boolean,
    ): String? {
        val domain = if (add) parseDomainLine(input) ?: return null else input
        val next = flow.value.toMutableSet().apply { if (add) add(domain) else remove(domain) }
        if (next == flow.value) return domain
        prefs.edit().putStringSet(key, next).apply()
        flow.value = next
        push()
        return domain
    }

    private fun load(key: String): Set<String> =
        prefs.getStringSet(key, emptySet())?.toSet() ?: emptySet()

    private fun push() {
        BlockList.get(app).applyUser(_block.value, _allow.value)
    }

    companion object {
        private const val KEY_BLOCK = "custom_block"
        private const val KEY_ALLOW = "allow_exceptions"

        @Volatile private var INSTANCE: UserDomains? = null

        fun get(context: Context): UserDomains =
            INSTANCE ?: synchronized(this) {
                INSTANCE ?: UserDomains(context.applicationContext).also { INSTANCE = it }
            }
    }
}
