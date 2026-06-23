package com.qopsec.firewall.data

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class ThemeMode { LIGHT, DARK, SYSTEM }

/**
 * Lightweight persisted settings (SharedPreferences) exposed as StateFlow for Compose.
 *
 * [askMode]: when true, an app with no rule has its first connection HELD and the user is
 * prompted (Allow/Block). When false, no rule = default-allow.
 */
class Settings private constructor(context: Context) {

    private val prefs =
        context.applicationContext.getSharedPreferences("qopsec_settings", Context.MODE_PRIVATE)

    private val _askMode = MutableStateFlow(prefs.getBoolean(KEY_ASK, false))
    val askMode: StateFlow<Boolean> = _askMode.asStateFlow()

    /** When true, the firewall starts deny-all on boot until the user unlocks (kill off). */
    private val _bootLock = MutableStateFlow(prefs.getBoolean(KEY_BOOT, false))
    val bootLock: StateFlow<Boolean> = _bootLock.asStateFlow()

    /** Master toggle for the ad/tracker blocker (DNS sinkhole + connection backstop). */
    private val _adBlock = MutableStateFlow(prefs.getBoolean(KEY_ADBLOCK, false))
    val adBlock: StateFlow<Boolean> = _adBlock.asStateFlow()

    /**
     * When true, deny connections to known encrypted-DNS resolvers (DoT/DoQ :853 + DoH on known
     * provider IPs/hosts) so apps can't bypass the plaintext-:53 sinkhole. Default off — it's
     * opinionated and can break apps that rely on a specific encrypted resolver.
     */
    private val _blockEncryptedDns = MutableStateFlow(prefs.getBoolean(KEY_ENCDNS, false))
    val blockEncryptedDns: StateFlow<Boolean> = _blockEncryptedDns.asStateFlow()

    /**
     * Upstream DNS resolver advertised to the system (addDnsServer) and thus where the relay
     * forwards non-sinkholed :53 queries. IPv4 only for now (IPv6 forwarding is dropped at the
     * netstack). Changing it needs a Stop→Start to re-establish the tunnel.
     */
    private val _dnsResolver = MutableStateFlow(prefs.getString(KEY_DNS, DEFAULT_DNS) ?: DEFAULT_DNS)
    val dnsResolver: StateFlow<String> = _dnsResolver.asStateFlow()

    private val _themeMode = MutableStateFlow(
        runCatching { ThemeMode.valueOf(prefs.getString(KEY_THEME, ThemeMode.SYSTEM.name)!!) }
            .getOrDefault(ThemeMode.SYSTEM),
    )
    val themeMode: StateFlow<ThemeMode> = _themeMode.asStateFlow()

    fun setAskMode(value: Boolean) {
        prefs.edit().putBoolean(KEY_ASK, value).apply()
        _askMode.value = value
    }

    fun setBootLock(value: Boolean) {
        prefs.edit().putBoolean(KEY_BOOT, value).apply()
        _bootLock.value = value
    }

    fun setThemeMode(mode: ThemeMode) {
        prefs.edit().putString(KEY_THEME, mode.name).apply()
        _themeMode.value = mode
    }

    fun setAdBlock(value: Boolean) {
        prefs.edit().putBoolean(KEY_ADBLOCK, value).apply()
        _adBlock.value = value
    }

    fun setBlockEncryptedDns(value: Boolean) {
        prefs.edit().putBoolean(KEY_ENCDNS, value).apply()
        _blockEncryptedDns.value = value
    }

    /** [ip] must be a valid IPv4 literal (validated by the caller). */
    fun setDnsResolver(ip: String) {
        prefs.edit().putString(KEY_DNS, ip).apply()
        _dnsResolver.value = ip
    }

    // --- Connections view: persisted status/kind/sort (plain strings; Compose holds the live
    // state, these just survive app restarts). Values are enum .name; callers tolerate bad reads.
    fun connFilter(): String = prefs.getString(KEY_CFILTER, "All") ?: "All"
    fun setConnFilter(v: String) = prefs.edit().putString(KEY_CFILTER, v).apply()
    fun connKind(): String = prefs.getString(KEY_CKIND, "Any") ?: "Any"
    fun setConnKind(v: String) = prefs.edit().putString(KEY_CKIND, v).apply()
    fun connSort(): String = prefs.getString(KEY_CSORT, "Recent") ?: "Recent"
    fun setConnSort(v: String) = prefs.edit().putString(KEY_CSORT, v).apply()

    companion object {
        private const val KEY_ASK = "ask_mode"
        private const val KEY_BOOT = "boot_lock"
        private const val KEY_THEME = "theme_mode"
        private const val KEY_ADBLOCK = "ad_block"
        private const val KEY_ENCDNS = "block_encrypted_dns"
        private const val KEY_DNS = "dns_resolver"
        private const val KEY_CFILTER = "conn_filter"
        private const val KEY_CKIND = "conn_kind"
        private const val KEY_CSORT = "conn_sort"
        const val DEFAULT_DNS = "1.1.1.1"

        @Volatile private var INSTANCE: Settings? = null

        fun get(context: Context): Settings =
            INSTANCE ?: synchronized(this) {
                INSTANCE ?: Settings(context).also { INSTANCE = it }
            }
    }
}
