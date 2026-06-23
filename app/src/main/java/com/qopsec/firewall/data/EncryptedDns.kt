package com.qopsec.firewall.data

/**
 * Detects connections to encrypted-DNS resolvers, so they can be denied to stop apps/browsers
 * from bypassing the plaintext-:53 ad-block sinkhole.
 *
 *  - **DoT / DoQ** use a dedicated port (853, TCP and UDP) — any flow to :853 is encrypted DNS.
 *  - **DoH** is just HTTPS (:443), so it can only be spotted by destination: a curated set of
 *    well-known public resolver IPs (DoH clients often connect by IP literal) plus their DoH
 *    hostnames (matched by domain suffix, when the host was learned via :53 first).
 *
 * This is necessarily a known-provider list, not exhaustive — a private/obscure DoH endpoint on
 * :443 is indistinguishable from normal HTTPS without deeper inspection. It covers the resolvers
 * that browsers and the OS actually auto-upgrade to (Chrome's "Secure DNS", Android Private DNS).
 *
 * Note: our own upstream relay talks to the resolver on :53 over a protected socket that bypasses
 * the tun, so blocking these :443/:853 endpoints never touches our own DNS forwarding.
 */
object EncryptedDns {

    /** Public resolver IPs that serve DoH on :443 (DoH clients frequently use IP literals). */
    private val bootstrapIps: Set<String> = hashSetOf(
        // Cloudflare
        "1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001",
        // Google
        "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844",
        // Quad9
        "9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9",
        // AdGuard DNS
        "94.140.14.14", "94.140.15.15", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff",
        // OpenDNS
        "208.67.222.222", "208.67.220.220",
    )

    /** Known DoH endpoint hostnames (matched by domain suffix → covers subdomains). */
    private val dohHosts: Set<String> = hashSetOf(
        "cloudflare-dns.com", "one.one.one.one",
        "dns.google", "dns.google.com",
        "dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net",
        "dns.adguard.com", "dns.adguard-dns.com", "dns-family.adguard.com",
        "doh.opendns.com", "doh.familyshield.opendns.com",
        "dns.nextdns.io", "doh.nextdns.io",
        "doh.cleanbrowsing.org", "doh.mullvad.net", "dns.controld.com",
    )

    /**
     * True if (ip/host, port) is a recognised encrypted-DNS endpoint that should be blocked when
     * "Block encrypted DNS" is on. [host] is the destination hostname if known (DNS cache / SNI).
     */
    fun isEncryptedDns(host: String?, ip: String, port: Int): Boolean {
        if (port == 853) return true                       // DoT (TCP) / DoQ (UDP)
        if (port == 443) {
            if (ip in bootstrapIps) return true            // DoH by resolver IP literal
            if (host != null && hostMatches(host)) return true  // DoH by hostname
        }
        return false
    }

    /** Label-walk suffix match: doh.dns.google matches dns.google. */
    private fun hostMatches(host: String): Boolean {
        var h = host.lowercase().removeSuffix(".")
        while (h.isNotEmpty()) {
            if (h in dohHosts) return true
            val dot = h.indexOf('.')
            if (dot < 0) return false
            h = h.substring(dot + 1)
        }
        return false
    }
}
