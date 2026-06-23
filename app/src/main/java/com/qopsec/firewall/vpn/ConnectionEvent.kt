package com.qopsec.firewall.vpn

/** Layer-4 protocol of an observed packet. */
enum class L4 { TCP, UDP, OTHER }

/**
 * One observed outbound flow, parsed from a packet read off the TUN.
 * Phase 1a enriches it with the owning app (uid/label) and, for DNS, the queried name.
 * Still metadata only — never payload beyond the DNS question.
 */
data class ConnectionEvent(
    val timeMs: Long,
    val ipVersion: Int,
    val protocol: L4,
    val srcIp: String,
    val srcPort: Int,
    val dstIp: String,
    val dstPort: Int,
    val dnsQuery: String? = null,
    val uid: Int = INVALID_UID,
    val appLabel: String? = null,
    val packageName: String? = null,
    val host: String? = null,          // resolved destination hostname (DNS cache), if known
    val verdict: Int = VERDICT_UNKNOWN, // VERDICT_ALLOW | VERDICT_DENY | VERDICT_UNKNOWN
) {
    companion object {
        const val INVALID_UID = -1
        const val VERDICT_UNKNOWN = -1
        const val VERDICT_ALLOW = 0
        const val VERDICT_DENY = 1
    }

    /**
     * Dedup key. DNS queries are keyed by name so each distinct lookup shows once;
     * everything else collapses by destination+protocol.
     */
    val key: String
        get() = if (dnsQuery != null) "DNS|$dnsQuery" else "$protocol|$dstIp|$dstPort"

    val destination: String get() = if (dstPort >= 0) "$dstIp:$dstPort" else dstIp

    /** What to show as the main line of a row. */
    val primary: String get() = when {
        host != null -> if (dstPort >= 0) "$host:$dstPort" else host
        dnsQuery != null -> "DNS? $dnsQuery"
        else -> destination
    }
}
