package com.qopsec.firewall.vpn

import java.util.concurrent.ConcurrentHashMap

/**
 * Best-effort IP -> hostname map, populated from DNS answers parsed by the Rust core
 * (NativeBridge.onDns). Lets the matcher turn an IP-level flow back into the hostname the
 * app asked for, so host rules ("block Facebook -> graph.facebook.com") can apply.
 *
 * Best-effort by nature: encrypted DNS (DoH/DoT) and IP-literal connections won't appear
 * here, and shared CDN IPs may map to whichever name was looked up most recently.
 */
object DnsCache {

    private data class Entry(val host: String, val expiresAt: Long)

    // Fixed TTL for slice 1; real per-record TTL can come later.
    private const val TTL_MS = 10 * 60_000L

    private val byIp = ConcurrentHashMap<String, Entry>()

    fun put(host: String, ip: String) {
        byIp[ip] = Entry(host, System.currentTimeMillis() + TTL_MS)
    }

    fun host(ip: String): String? {
        val e = byIp[ip] ?: return null
        if (e.expiresAt < System.currentTimeMillis()) {
            byIp.remove(ip)
            return null
        }
        return e.host
    }
}
