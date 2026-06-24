package com.qopsec.firewall.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.net.Inet6Address
import java.net.InetAddress
import android.widget.RemoteViews
import androidx.core.app.NotificationCompat
import com.qopsec.firewall.BuildConfig
import com.qopsec.firewall.MainActivity
import com.qopsec.firewall.R
import com.qopsec.firewall.data.BlockList
import com.qopsec.firewall.data.BlocklistManager
import com.qopsec.firewall.data.AppPolicy
import com.qopsec.firewall.data.ConnLog
import com.qopsec.firewall.data.EncryptedDns
import com.qopsec.firewall.data.Rule
import com.qopsec.firewall.data.RuleRepository
import com.qopsec.firewall.data.UserDomains
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.IOException

/**
 * Firewall tunnel service.
 *
 * Establishes a local VpnService tunnel with a catch-all route so ALL traffic enters
 * our TUN. From there, two modes:
 *
 *  - **Native (Phase 1b/2):** if [NativeBridge] is available, we hand the TUN fd to the
 *    Rust core, which terminates each flow on a smoltcp stack and re-originates it
 *    through OS sockets we [protect]. For each new flow the core calls [decide]
 *    synchronously for a rule verdict (allow/deny); allowed flows are relayed (working
 *    internet), denied flows dropped. Default-allow until rules say otherwise.
 *
 *  - **Fallback (Phase 1a):** if the native lib isn't built, we keep the original
 *    read-and-drop loop: we observe every connection but forward nothing, so traffic is
 *    paused while running. Lets the app stay useful without the Rust toolchain.
 */
class VpnFirewallService : VpnService() {

    companion object {
        const val ACTION_START = "com.qopsec.firewall.action.START"
        const val ACTION_STOP = "com.qopsec.firewall.action.STOP"
        const val ACTION_ALLOW_APP = "com.qopsec.firewall.action.ALLOW_APP"
        const val ACTION_BLOCK_APP = "com.qopsec.firewall.action.BLOCK_APP"
        const val ACTION_KILL_ON = "com.qopsec.firewall.action.KILL_ON"
        const val ACTION_KILL_OFF = "com.qopsec.firewall.action.KILL_OFF"
        const val EXTRA_BOOT_LOCK = "boot_lock"
        private const val EXTRA_UID = "uid"
        private const val EXTRA_PKG = "pkg"
        private const val EXTRA_LABEL = "label"

        // Engine modes for nativeSetMode (must match Rust MODE_*).
        private const val MODE_FILTER = 1
        private const val MODE_DENY = 2

        // ⚠️ TEMPORARY DIAGNOSTIC (stop-hang investigation 2026-06-24): verbose teardown logging.
        // Remove these Log.* calls + this TAG once the stop bug is fixed.
        private const val TAG = "qopsec_fw"

        private const val CHANNEL_ID = "capture"
        private const val PROMPT_CHANNEL_ID = "prompts"
        private const val NOTIF_ID = 1
        private const val REVOKE_NOTIF_ID = 3
        private const val PROMPT_NOTIF_BASE = 2_000_000   // keep prompt ids clear of NOTIF_ID
        private const val MTU = 1500
        private const val READ_BUF = 32_767

        // Verdict returned to the Rust core (matches VERDICT_* there).
        private const val ALLOW = 0
        private const val DENY = 1
        private const val PENDING = 2
    }

    @Volatile private var running = false
    private var tun: ParcelFileDescriptor? = null
    private var reader: Thread? = null
    private var nativeHandle: Long = 0L
    private var netCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile private var ipv6Fwd: Boolean? = null   // last value pushed to the core (dedup)
    private val resolver by lazy { AppResolver(this) }
    private val rules by lazy { RuleRepository.get(this) }
    private val settings by lazy { com.qopsec.firewall.data.Settings.get(this) }
    private val blockList by lazy { BlockList.get(this) }
    private val appPolicy by lazy { AppPolicy.get(this) }
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Apps with an outstanding prompt — coalesces to one notification per app.
    private val pendingApps = java.util.Collections.synchronizedSet(HashSet<Int>())

    // Phase 1a fallback only: dedup conn_log writes to one per distinct flow.
    private val fallbackSeen = java.util.Collections.synchronizedSet(HashSet<String>())

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(TAG, "onStartCommand action=${intent?.action} thread=${Thread.currentThread().name} running=$running")
        when (intent?.action) {
            ACTION_STOP -> {
                Log.i(TAG, "onStartCommand: ACTION_STOP -> stopCapture()")
                stopCapture()
                Log.i(TAG, "onStartCommand: stopCapture() returned -> START_NOT_STICKY")
                return START_NOT_STICKY
            }
            ACTION_ALLOW_APP -> resolvePrompt(intent, Rule.ACTION_ALLOW)
            ACTION_BLOCK_APP -> resolvePrompt(intent, Rule.ACTION_DENY)
            ACTION_KILL_ON -> setKill(true)
            ACTION_KILL_OFF -> setKill(false)
            else -> startCapture(bootLock = intent?.getBooleanExtra(EXTRA_BOOT_LOCK, false) == true)
        }
        return START_STICKY
    }

    private fun startCapture(bootLock: Boolean = false) {
        if (running) {
            // Already up — a boot-lock (re)start just engages the kill switch.
            if (bootLock) setKill(true)
            return
        }
        createChannel()
        startForeground(NOTIF_ID, buildNotification())

        val builder = Builder()
            .setSession(getString(R.string.app_name))
            .addAddress("10.0.0.2", 32)
            .addAddress("fd00:0:0:0:0:0:0:2", 128)
            .addRoute("0.0.0.0", 0)     // capture all IPv4
            .addRoute("::", 0)          // capture all IPv6
            // Advertise a DNS server so the SYSTEM resolver (netd) sends queries THROUGH the
            // tun — otherwise it resolves around us and the ad-block DNS sinkhole never sees
            // them. Non-blocked queries are relayed on to this resolver; blocked ones are
            // answered locally with NXDOMAIN. (DoH/DoT still bypass — a known limitation.)
            // User-configurable (Settings.dnsResolver); changing it needs a Stop→Start.
            .addDnsServer(settings.dnsResolver.value)
            .setMtu(MTU)
            .setBlocking(true)

        // Per-app firewall exclusion (slice 4d): these apps are split-tunnelled OUT of the VPN —
        // their traffic never enters our tun (complete bypass: no filtering/capture/kill switch).
        for (pkg in appPolicy.excludedPackages()) {
            runCatching { builder.addDisallowedApplication(pkg) }  // ignore uninstalled packages
        }

        val pfd = try {
            builder.establish()
        } catch (e: Exception) {
            null
        }

        if (pfd == null) {
            stopSelf()
            return
        }

        running = true
        CaptureLog.setRunning(true)
        Log.i(TAG, "startCapture: tunnel established (native=${NativeBridge.available}, bootLock=$bootLock)")

        if (NativeBridge.available) {
            startNativeForwarding(pfd)
        } else {
            tun = pfd
            reader = Thread({ readLoop(pfd) }, "tun-reader").also { it.start() }
        }

        // Boot-lock: come up in deny-all until the user unlocks (toggles kill off).
        setKill(bootLock)
    }

    /** Engage/release the kill switch: deny-all (tunnel stays up) ↔ normal filtering. */
    private fun setKill(on: Boolean) {
        if (!running) return
        if (nativeHandle != 0L) {
            NativeBridge.nativeSetMode(nativeHandle, if (on) MODE_DENY else MODE_FILTER)
        }
        CaptureLog.setKilled(on)
        getSystemService(NotificationManager::class.java).notify(NOTIF_ID, buildNotification())
    }

    /** Phase 1b/2: hand the (detached) fd to the Rust core; it owns and closes it. */
    private fun startNativeForwarding(pfd: ParcelFileDescriptor) {
        NativeBridge.protector = { fd -> protect(fd) }
        NativeBridge.dnsSink = { host, ip -> DnsCache.put(host, ip) }
        NativeBridge.decider = { proto, srcIp, srcPort, dstIp, dstPort ->
            decide(proto, srcIp, srcPort, dstIp, dstPort)
        }
        NativeBridge.blockHostChecker = { host ->
            settings.adBlock.value && blockList.isBlocked(host)
        }
        BlocklistManager.get(this)   // ensure subscribed lists are merged (e.g. boot-lock path)
        UserDomains.get(this)        // ensure custom-block + allowlist exceptions are merged too
        // detachFd transfers ownership: the PFD won't close the fd; the core will.
        val fd = pfd.detachFd()
        Log.i(TAG, "startNativeForwarding: detached tun fd=$fd -> nativeStart")
        nativeHandle = NativeBridge.nativeStart(fd, BuildConfig.DEBUG)
        Log.i(TAG, "startNativeForwarding: nativeStart returned handle=$nativeHandle")
        if (nativeHandle == 0L) {
            // Native start failed: we already gave up the fd, so just stop cleanly.
            stopCapture()
            return
        }

        // Gate IPv6 forwarding on real v6 egress, and keep it updated as networks change.
        updateIpv6()
        registerNetworkCallback()

        // Re-evaluate live flows whenever the rule set changes, so a block/allow takes
        // effect on already-open connections instantly (not just on the next new flow).
        scope.launch {
            var first = true
            rules.allRules.collect {
                if (first) {
                    first = false
                } else if (nativeHandle != 0L) {
                    NativeBridge.nativeReevaluate(nativeHandle)
                }
            }
        }
    }

    // --- IPv6 forwarding gate ---

    /**
     * True if any non-VPN network has a GLOBAL-unicast IPv6 address (2000::/3) — our proxy for
     * "v6 actually routes to the internet". On networks with only link-local / site-local (fec0::)
     * / ULA (fc00::/7) v6 (e.g. the emulator), this is false, so we drop v6 and apps use IPv4.
     */
    private fun hasGlobalIpv6(): Boolean {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return false
        return cm.allNetworks.any { net ->
            val caps = cm.getNetworkCapabilities(net)
            if (caps == null || caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return@any false
            cm.getLinkProperties(net)?.linkAddresses?.any { isGlobalUnicastV6(it.address) } == true
        }
    }

    private fun isGlobalUnicastV6(a: InetAddress): Boolean {
        if (a !is Inet6Address) return false
        if (a.isLinkLocalAddress || a.isLoopbackAddress || a.isSiteLocalAddress ||
            a.isAnyLocalAddress || a.isMulticastAddress
        ) return false
        // 2000::/3 global unicast (also excludes ULA fc00::/7 = 0xFC/0xFD).
        return (a.address[0].toInt() and 0xE0) == 0x20
    }

    private fun registerNetworkCallback() {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = updateIpv6()
            override fun onLost(network: Network) = updateIpv6()
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) = updateIpv6()
            override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) = updateIpv6()
        }
        netCallback = cb
        runCatching {
            cm.registerNetworkCallback(
                NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).build(),
                cb,
            )
        }
    }

    /** Re-detect v6 egress and push to the core only when it changes (new flows follow it). */
    private fun updateIpv6() {
        if (!running || nativeHandle == 0L) return
        val v6 = hasGlobalIpv6()
        if (v6 != ipv6Fwd) {
            ipv6Fwd = v6
            NativeBridge.nativeSetIpv6(v6)
        }
    }

    private fun unregisterNetworkCallback() {
        netCallback?.let { cb ->
            runCatching { getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(cb) }
        }
        netCallback = null
    }

    /**
     * Phase 2 decision callback — invoked SYNCHRONOUSLY by the Rust core per new flow.
     * Resolve the owning app, look up the host, match rules. Returns ALLOW/DENY, or PENDING
     * (ask-mode, no rule yet) after raising a prompt. conn-log recording is off the hot path.
     */
    private fun decide(proto: Int, srcIp: String, srcPort: Int, dstIp: String, dstPort: Int): Int {
        val l4 = when (proto) {
            6 -> L4.TCP
            17 -> L4.UDP
            else -> L4.OTHER
        }
        val host = DnsCache.host(dstIp)
        val probe = ConnectionEvent(0L, 0, l4, srcIp, srcPort, dstIp, dstPort)
        val uid = resolver.ownerUid(probe)
        val pkg = resolver.packageOf(uid)
        val decision = rules.decide(uid, pkg, proto, dstIp, host, dstPort)

        // Per-app ad-block exemption (slice 4d): excluded apps bypass the ad-block backstop. The DNS
        // sinkhole stays system-wide (no uid at :53), so this exempts their connection-level traffic.
        val adBlockActive = settings.adBlock.value && !appPolicy.isAdBlockExempt(pkg)

        val action = when {
            decision.rule != null -> decision.action          // explicit rule: honor it (allowlist wins)
            // Ad/tracker backstop: catches blocked hosts the DNS sinkhole missed (cached/IP-literal/SNI).
            adBlockActive && host != null && blockList.isBlocked(host) -> DENY
            // Encrypted-DNS backstop: stop apps escaping the :53 sinkhole via DoT/DoQ/DoH.
            settings.blockEncryptedDns.value && EncryptedDns.isEncryptedDns(host, dstIp, dstPort) -> DENY
            !settings.askMode.value -> ALLOW                  // ask-mode off: default allow
            uid < 0 -> ALLOW                                  // can't attribute -> can't prompt
            else -> {                                          // unknown app: prompt + hold
                requestPrompt(uid, pkg, resolver.label(uid), host ?: "$dstIp:$dstPort")
                PENDING
            }
        }

        scope.launch {
            rules.recordConn(
                ConnLog(
                    flowKey = "$uid|$proto|$dstIp|$dstPort",
                    ts = System.currentTimeMillis(),
                    appUid = uid,
                    appLabel = resolver.label(uid),
                    packageName = pkg,
                    proto = proto,
                    ipVersion = if (dstIp.contains(':')) 6 else 4,
                    dstIp = dstIp,
                    dstHost = host,
                    dstPort = dstPort,
                )
            )
        }
        return action
    }

    // --- ask-mode prompts ---

    /** Post one Allow/Block notification per app (coalesced); off the datapath thread. */
    private fun requestPrompt(uid: Int, pkg: String?, label: String, dest: String) {
        if (!pendingApps.add(uid)) return
        scope.launch { postPrompt(uid, pkg, label, dest) }
    }

    private fun postPrompt(uid: Int, pkg: String?, label: String, dest: String) {
        val nm = getSystemService(NotificationManager::class.java)
        createPromptChannel(nm)
        val n = NotificationCompat.Builder(this, PROMPT_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle("Allow $label?")
            .setContentText("$label wants to connect to $dest")
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_RECOMMENDATION)
            .setAutoCancel(true)
            .addAction(0, "Allow", promptPendingIntent(uid, pkg, label, ACTION_ALLOW_APP, uid * 2))
            .addAction(0, "Block", promptPendingIntent(uid, pkg, label, ACTION_BLOCK_APP, uid * 2 + 1))
            .build()
        nm.notify(PROMPT_NOTIF_BASE + uid, n)
    }

    private fun promptPendingIntent(
        uid: Int,
        pkg: String?,
        label: String,
        action: String,
        requestCode: Int,
    ): PendingIntent {
        val i = Intent(this, VpnFirewallService::class.java)
            .setAction(action)
            .putExtra(EXTRA_UID, uid)
            .putExtra(EXTRA_PKG, pkg)
            .putExtra(EXTRA_LABEL, label)
        return PendingIntent.getService(
            this, requestCode, i,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
    }

    /** Handle an Allow/Block tap from a prompt notification: write the app rule + clear it. */
    private fun resolvePrompt(intent: Intent, action: Int) {
        val uid = intent.getIntExtra(EXTRA_UID, -1)
        if (uid < 0) return
        val pkg = intent.getStringExtra(EXTRA_PKG)
        val label = intent.getStringExtra(EXTRA_LABEL)
        rules.setAppRule(uid, pkg, label, action)   // rule change -> nativeReevaluate resumes/drops held flows
        pendingApps.remove(uid)
        getSystemService(NotificationManager::class.java).cancel(PROMPT_NOTIF_BASE + uid)
    }

    private fun clearPrompts() {
        val nm = getSystemService(NotificationManager::class.java)
        synchronized(pendingApps) {
            pendingApps.forEach { nm.cancel(PROMPT_NOTIF_BASE + it) }
            pendingApps.clear()
        }
    }

    /** Phase 1a fallback: observe + drop (no forwarding -> traffic paused). */
    private fun readLoop(pfd: ParcelFileDescriptor) {
        val input = FileInputStream(pfd.fileDescriptor)
        val buf = ByteArray(READ_BUF)
        try {
            while (running) {
                val n = input.read(buf)
                if (n < 0) break          // tun closed
                if (n == 0) continue
                PacketParser.parse(buf, n)?.let { ev ->
                    val e = resolver.enrich(ev)
                    val proto = when (e.protocol) { L4.TCP -> 6; L4.UDP -> 17; else -> 0 }
                    val key = "${e.uid}|$proto|${e.dstIp}|${e.dstPort}"
                    if (fallbackSeen.add(key)) {
                        scope.launch {
                            rules.recordConn(
                                ConnLog(
                                    flowKey = key,
                                    ts = System.currentTimeMillis(),
                                    appUid = e.uid,
                                    appLabel = e.appLabel,
                                    packageName = e.packageName,
                                    proto = proto,
                                    ipVersion = e.ipVersion,
                                    dstIp = e.dstIp,
                                    dstHost = e.dnsQuery,
                                    dstPort = e.dstPort,
                                )
                            )
                        }
                    }
                }
            }
        } catch (e: IOException) {
            // expected when the tunnel is torn down
        } finally {
            try { input.close() } catch (_: Exception) {}
        }
    }

    private fun stopCapture() {
        val t0 = System.currentTimeMillis()
        Log.i(TAG, "stopCapture: ENTER running=$running handle=$nativeHandle thread=${Thread.currentThread().name}")
        running = false
        CaptureLog.setRunning(false)
        CaptureLog.setKilled(false)
        Log.i(TAG, "stopCapture: CaptureLog set to stopped (UI now shows stopped)")

        if (nativeHandle != 0L) {
            Log.i(TAG, "stopCapture: calling NativeBridge.nativeStop($nativeHandle) -- watch for it to return")
            NativeBridge.nativeStop(nativeHandle)   // also closes the tun fd it owns
            Log.i(TAG, "stopCapture: nativeStop() RETURNED after ${System.currentTimeMillis() - t0}ms")
            nativeHandle = 0L
        } else {
            Log.i(TAG, "stopCapture: nativeHandle already 0 (no native engine to stop)")
        }
        NativeBridge.protector = null
        NativeBridge.decider = null
        NativeBridge.dnsSink = null
        NativeBridge.blockHostChecker = null
        unregisterNetworkCallback()
        ipv6Fwd = null
        clearPrompts()
        fallbackSeen.clear()
        Log.i(TAG, "stopCapture: callbacks cleared, netcallback unregistered")

        try { tun?.close() } catch (_: Exception) {}
        tun = null
        reader?.interrupt()
        reader = null

        Log.i(TAG, "stopCapture: calling stopForeground + stopSelf")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        Log.i(TAG, "stopCapture: DONE in ${System.currentTimeMillis() - t0}ms (service stopping)")
    }

    /** The OS calls this when another VPN takes over — stop cleanly so we never silently linger. */
    override fun onRevoke() {
        Log.i(TAG, "onRevoke: another VPN took over -> stopCapture")
        notifyRevoked()
        stopCapture()
        super.onRevoke()
    }

    /** Tell the user the firewall went down because another VPN replaced it (not a silent failure). */
    private fun notifyRevoked() {
        val nm = getSystemService(NotificationManager::class.java)
        createPromptChannel(nm)   // HIGH importance, so it's a noticeable heads-up
        val openApp = PendingIntent.getActivity(
            this, 20,
            Intent(this, com.qopsec.firewall.MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val n = NotificationCompat.Builder(this, PROMPT_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle("Firewall stopped")
            .setContentText("Another VPN took over the connection — protection is off.")
            .setContentIntent(openApp)
            .setAutoCancel(true)
            .build()
        nm.notify(REVOKE_NOTIF_ID, n)
    }

    override fun onDestroy() {
        Log.i(TAG, "onDestroy: service being destroyed -> stopCapture")
        stopCapture()
        scope.cancel()
        super.onDestroy()
    }

    // --- notification plumbing ---

    private fun createChannel() {
        val nm = getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    getString(R.string.channel_name),
                    NotificationManager.IMPORTANCE_LOW
                )
            )
        }
    }

    private fun createPromptChannel(nm: NotificationManager) {
        if (nm.getNotificationChannel(PROMPT_CHANNEL_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(
                    PROMPT_CHANNEL_ID,
                    getString(R.string.prompt_channel_name),
                    NotificationManager.IMPORTANCE_HIGH,
                )
            )
        }
    }

    private fun buildNotification(): Notification {
        val open = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val killed = CaptureLog.killed.value
        val title = if (killed) "Kill switch ON" else getString(R.string.notif_title)
        val text = when {
            killed -> "All traffic blocked"
            NativeBridge.available -> getString(R.string.notif_text)
            else -> getString(R.string.notif_text_paused)
        }

        // Custom view so the kill toggle is a coloured pill button matching the app's
        // blocked (red) / allowed (green) status style, not a plain text action.
        val view = RemoteViews(packageName, R.layout.notif_firewall).apply {
            setTextViewText(R.id.notif_title, title)
            setTextViewText(R.id.notif_text, text)
            if (killed) {
                setTextViewText(R.id.notif_button, "RESUME")
                setInt(R.id.notif_button, "setBackgroundResource", R.drawable.bg_pill_green)
                setOnClickPendingIntent(R.id.notif_button, servicePendingIntent(ACTION_KILL_OFF, 11))
            } else {
                setTextViewText(R.id.notif_button, "KILL")
                setInt(R.id.notif_button, "setBackgroundResource", R.drawable.bg_pill_red)
                setOnClickPendingIntent(R.id.notif_button, servicePendingIntent(ACTION_KILL_ON, 10))
            }
        }

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setColor(0xFFEF4444.toInt())
            .setOngoing(true)
            .setContentIntent(open)
            .setStyle(NotificationCompat.DecoratedCustomViewStyle())
            .setCustomContentView(view)
            .build()
    }

    private fun servicePendingIntent(action: String, requestCode: Int): PendingIntent =
        PendingIntent.getService(
            this, requestCode,
            Intent(this, VpnFirewallService::class.java).setAction(action),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
}
