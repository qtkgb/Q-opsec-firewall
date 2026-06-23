package com.qopsec.firewall.vpn

import java.net.InetAddress

/**
 * Minimal IPv4/IPv6 header parser — extracts the 5-tuple, and for UDP/53 the DNS
 * query name (QNAME) from the question section.
 *
 * Phase 1a scope: no IPv6 extension-header walking, no fragmentation, no DNS name
 * compression in the question (questions don't use it). This whole surface moves into
 * the memory-safe Rust core later (report finding N-1).
 */
object PacketParser {

    private const val PROTO_TCP = 6
    private const val PROTO_UDP = 17
    private const val DNS_PORT = 53

    fun parse(buf: ByteArray, len: Int): ConnectionEvent? {
        if (len < 1) return null
        return when ((buf[0].toInt() ushr 4) and 0xF) {
            4 -> parseV4(buf, len)
            6 -> parseV6(buf, len)
            else -> null
        }
    }

    private fun u8(b: Byte) = b.toInt() and 0xFF

    private fun parseV4(buf: ByteArray, len: Int): ConnectionEvent? {
        if (len < 20) return null
        val ihl = (u8(buf[0]) and 0x0F) * 4
        if (ihl < 20 || len < ihl) return null
        val proto = u8(buf[9])
        val src = ipString(buf, 12, 4) ?: return null
        val dst = ipString(buf, 16, 4) ?: return null
        return build(buf, len, ihl, proto, 4, src, dst)
    }

    private fun parseV6(buf: ByteArray, len: Int): ConnectionEvent? {
        if (len < 40) return null
        val next = u8(buf[6])               // next header (no extension walking in Phase 1a)
        val src = ipString(buf, 8, 16) ?: return null
        val dst = ipString(buf, 24, 16) ?: return null
        return build(buf, len, 40, next, 6, src, dst)
    }

    private fun build(
        buf: ByteArray, len: Int, l4Off: Int, proto: Int,
        ipVersion: Int, src: String, dst: String,
    ): ConnectionEvent {
        val kind = when (proto) {
            PROTO_TCP -> L4.TCP
            PROTO_UDP -> L4.UDP
            else -> L4.OTHER
        }
        var sp = -1
        var dp = -1
        var dns: String? = null
        if (kind != L4.OTHER && len >= l4Off + 4) {
            sp = (u8(buf[l4Off]) shl 8) or u8(buf[l4Off + 1])
            dp = (u8(buf[l4Off + 2]) shl 8) or u8(buf[l4Off + 3])
            if (kind == L4.UDP && dp == DNS_PORT) {
                dns = parseDnsQName(buf, l4Off + 8, len)   // UDP header is 8 bytes
            }
        }
        return ConnectionEvent(System.currentTimeMillis(), ipVersion, kind, src, sp, dst, dp, dns)
    }

    /** Read the first QNAME from a DNS message starting at [udpPayloadOff]. */
    private fun parseDnsQName(buf: ByteArray, udpPayloadOff: Int, len: Int): String? {
        var pos = udpPayloadOff + 12          // skip the 12-byte DNS header
        if (pos >= len) return null
        val sb = StringBuilder()
        while (pos < len) {
            val l = u8(buf[pos]); pos++
            if (l == 0) break
            if (l and 0xC0 != 0) return null  // compression pointer — not used in questions
            if (pos + l > len) return null
            if (sb.isNotEmpty()) sb.append('.')
            for (i in 0 until l) sb.append((u8(buf[pos + i])).toChar())
            pos += l
        }
        return sb.takeIf { it.isNotEmpty() }?.toString()
    }

    /** Format an address with no DNS lookup (getByAddress is offline). */
    private fun ipString(buf: ByteArray, off: Int, size: Int): String? {
        if (off + size > buf.size) return null
        val raw = ByteArray(size)
        System.arraycopy(buf, off, raw, 0, size)
        return try {
            InetAddress.getByAddress(raw).hostAddress
        } catch (e: Exception) {
            null
        }
    }
}
