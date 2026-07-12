package com.qopsec.firewall.vpn

/**
 * Kotlin side of the Rust datapath bridge (libfirewall_core.so).
 *
 * Loading is fault-tolerant: if the native library hasn't been built yet (Rust/NDK
 * toolchain not installed), the app still runs and reports "not built" instead of
 * crashing, falling back to the Phase 1a capture-and-drop loop. See RUST_SETUP.md.
 *
 * The core calls back UP into Kotlin on its own (native) threads:
 *  - [protectFd]  -> VpnService.protect(fd), so the relay's OS sockets bypass our tun.
 *  - [decideFlow] -> rule verdict (0 allow / 1 deny) per new flow; also feeds the live list.
 *  - [onDns]      -> a learned (host, ip) DNS mapping for host-rule matching.
 * The running [VpnFirewallService] registers [protector], [decider] and [dnsSink] while active.
 */
object NativeBridge {

    val available: Boolean = try {
        System.loadLibrary("firewall_core")
        true
    } catch (t: Throwable) {
        false
    }

    /** Set by the service to VpnService.protect; returns true if the socket was protected. */
    @Volatile
    @JvmField
    var protector: ((Int) -> Boolean)? = null

    /**
     * Set by the service. Called synchronously per new flow; must return a verdict
     * (0 allow / 1 deny) quickly. Default allow if unset.
     */
    @Volatile
    @JvmField
    var decider: ((proto: Int, srcIp: String, srcPort: Int, dstIp: String, dstPort: Int) -> Int)? = null

    /** Set by the service; receives a learned (host, ip) DNS mapping. */
    @Volatile
    @JvmField
    var dnsSink: ((host: String, ip: String) -> Unit)? = null

    /** Set by the service; returns true if a DNS query name should be sinkholed (ad/tracker). */
    @Volatile
    @JvmField
    var blockHostChecker: ((host: String) -> Boolean)? = null

    /**
     * Set by the service. Called from the native watchdog when the datapath has wedged (forwarding
     * stalled under load). The service fails open — tears the tunnel down so internet is restored
     * rather than blackholed. Called on a native thread; the handler must hop to the main thread.
     */
    @Volatile
    @JvmField
    var staller: (() -> Unit)? = null

    /**
     * Set by the service; receives a flow's byte delta (periodic for long flows + a final
     * report at flow end) for the Stats per-app usage buckets. Native threads.
     */
    @Volatile
    @JvmField
    var bytesSink: ((proto: Int, srcIp: String, srcPort: Int, dstIp: String, dstPort: Int, rx: Long, tx: Long) -> Unit)? = null

    private external fun nativeVersion(): String

    /** [logLevel]: 0 off / 1 info (lifecycle) / 2 debug (per-connection). See DiagLevel.toNative(). */
    external fun nativeStart(tunFd: Int, logLevel: Int): Long
    external fun nativeStop(handle: Long)
    external fun nativeSetMode(handle: Long, mode: Int)

    /** Change the core's log verbosity live (0 off / 1 info / 2 debug) without a restart. */
    external fun nativeSetLogLevel(level: Int)

    /** Ask the core to re-check active flows against current rules and drop newly-denied ones. */
    external fun nativeReevaluate(handle: Long)

    /** Enable/disable IPv6 forwarding (set from real v6-egress detection). Off = drop v6 → v4 fallback. */
    external fun nativeSetIpv6(enabled: Boolean)

    fun version(): String? =
        if (available) runCatching { nativeVersion() }.getOrNull() else null

    fun status(): String = version() ?: "not built (see RUST_SETUP.md)"

    // --- called from native (tokio) threads ---

    @JvmStatic
    fun protectFd(fd: Int): Boolean = protector?.invoke(fd) ?: false

    @JvmStatic
    fun decideFlow(proto: Int, srcIp: String, srcPort: Int, dstIp: String, dstPort: Int): Int =
        decider?.invoke(proto, srcIp, srcPort, dstIp, dstPort) ?: 0  // fail-open: allow

    @JvmStatic
    fun onDns(host: String, ip: String) {
        dnsSink?.invoke(host, ip)
    }

    @JvmStatic
    fun isBlockedHost(host: String): Boolean = blockHostChecker?.invoke(host) ?: false

    @JvmStatic
    fun onStall() {
        staller?.invoke()
    }

    @JvmStatic
    fun onFlowBytes(proto: Int, srcIp: String, srcPort: Int, dstIp: String, dstPort: Int, rx: Long, tx: Long) {
        bytesSink?.invoke(proto, srcIp, srcPort, dstIp, dstPort, rx, tx)
    }
}
