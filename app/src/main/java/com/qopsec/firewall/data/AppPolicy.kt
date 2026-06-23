package com.qopsec.firewall.data

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Per-app policy (slice 4d), persisted in SharedPreferences as two package-name sets:
 *
 *  - [adBlockExempt] — apps exempt from ad/tracker blocking. Enforced at the connection backstop
 *    in `decide()` (uid is known there). The DNS sinkhole is system-wide and can't be per-app, so
 *    an exempt app's plain system-DNS lookups of ad domains are still sinkholed — exemption fully
 *    applies only to its cached / IP-literal / encrypted-DNS / SNI connections.
 *
 *  - [firewallExcluded] — apps removed from the VPN entirely via
 *    `VpnService.Builder.addDisallowedApplication`, so their traffic never enters our tun. This is
 *    a COMPLETE exemption (DNS + connections) but also drops the app from all firewall features
 *    (capture, rules, kill switch). Applied at tunnel establish → needs a Stop→Start to take effect.
 */
class AppPolicy private constructor(context: Context) {

    private val prefs =
        context.applicationContext.getSharedPreferences("qopsec_apppolicy", Context.MODE_PRIVATE)

    private val _adBlockExempt = MutableStateFlow(load(KEY_ADBLOCK_EXEMPT))
    val adBlockExempt: StateFlow<Set<String>> = _adBlockExempt.asStateFlow()

    private val _firewallExcluded = MutableStateFlow(load(KEY_FW_EXCLUDED))
    val firewallExcluded: StateFlow<Set<String>> = _firewallExcluded.asStateFlow()

    /** Hot-path check (called per flow in decide()). */
    fun isAdBlockExempt(pkg: String?): Boolean = pkg != null && pkg in _adBlockExempt.value

    /** Read at tunnel establish to wire addDisallowedApplication. */
    fun excludedPackages(): Set<String> = _firewallExcluded.value

    fun setAdBlockExempt(pkg: String, on: Boolean) = mutate(KEY_ADBLOCK_EXEMPT, _adBlockExempt, pkg, on)

    fun setFirewallExcluded(pkg: String, on: Boolean) = mutate(KEY_FW_EXCLUDED, _firewallExcluded, pkg, on)

    private fun mutate(key: String, flow: MutableStateFlow<Set<String>>, pkg: String, on: Boolean) {
        val next = flow.value.toMutableSet().apply { if (on) add(pkg) else remove(pkg) }
        if (next == flow.value) return
        prefs.edit().putStringSet(key, next).apply()
        flow.value = next
    }

    private fun load(key: String): Set<String> =
        prefs.getStringSet(key, emptySet())?.toSet() ?: emptySet()

    companion object {
        private const val KEY_ADBLOCK_EXEMPT = "adblock_exempt"
        private const val KEY_FW_EXCLUDED = "fw_excluded"

        @Volatile private var INSTANCE: AppPolicy? = null

        fun get(context: Context): AppPolicy =
            INSTANCE ?: synchronized(this) {
                INSTANCE ?: AppPolicy(context.applicationContext).also { INSTANCE = it }
            }
    }
}
