package com.qopsec.firewall.vpn

import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.os.Process
import android.os.SystemClock
import android.system.OsConstants
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * Resolves which app owns a captured flow.
 *
 * Uses [ConnectivityManager.getConnectionOwnerUid] (API 29+, the reason minSdk = 29).
 * As the active VPN, this app is allowed to attribute other apps' connections.
 * Results are cached: UID per flow 5-tuple, and label per UID — so we make at most one
 * binder call per new flow.
 */
class AppResolver(context: Context) {

    companion object {
        private const val UID_LOOKUP_ATTEMPTS = 4
        private const val UID_RETRY_DELAY_MS = 5L   // progressive: 5/10/15 ms between attempts
    }

    private val cm = context.getSystemService(ConnectivityManager::class.java)
    private val pm: PackageManager = context.packageManager
    private val ownUid = Process.myUid()

    private val uidByFlow = ConcurrentHashMap<String, Int>()
    private val labelByUid = ConcurrentHashMap<Int, String>()

    /** Returns owning UID for a TCP/UDP flow, or [ConnectionEvent.INVALID_UID]. */
    fun ownerUid(event: ConnectionEvent): Int {
        if (event.protocol == L4.OTHER || event.srcPort < 0 || event.dstPort < 0) {
            return ConnectionEvent.INVALID_UID
        }
        val flowKey = "${event.protocol}|${event.srcIp}:${event.srcPort}|${event.dstIp}:${event.dstPort}"
        uidByFlow[flowKey]?.let { return it }

        val proto = if (event.protocol == L4.TCP) OsConstants.IPPROTO_TCP else OsConstants.IPPROTO_UDP
        val src = InetSocketAddress(InetAddress.getByName(event.srcIp), event.srcPort)
        val dst = InetSocketAddress(InetAddress.getByName(event.dstIp), event.dstPort)

        // The kernel's socket table may not have the app's socket yet when we see its first
        // SYN (connection bursts lose this race and come back as -1, or 0 while the socket is
        // still kernel-owned) — retry briefly, and never cache a failed lookup so the flow's
        // next packet gets another chance instead of being branded root/unknown forever.
        var uid = ConnectionEvent.INVALID_UID
        for (attempt in 0 until UID_LOOKUP_ATTEMPTS) {
            if (attempt > 0) SystemClock.sleep(UID_RETRY_DELAY_MS * attempt)
            uid = try {
                cm.getConnectionOwnerUid(proto, src, dst)
            } catch (e: Exception) {
                ConnectionEvent.INVALID_UID
            }
            if (uid > 0) {
                uidByFlow[flowKey] = uid
                break
            }
        }
        return uid
    }

    /** First package name owning a UID, or null. Used to make app rules survive uid churn. */
    fun packageOf(uid: Int): String? =
        if (uid < 0) null else pm.getPackagesForUid(uid)?.firstOrNull()

    /** Human label for a UID (app name, or a sensible fallback). */
    fun label(uid: Int): String = when {
        uid < 0 -> "unknown"
        uid == 0 -> "root"
        uid == ownUid -> "Q opsec firewall"
        else -> labelByUid.getOrPut(uid) {
            val pkgs = pm.getPackagesForUid(uid)
            if (pkgs.isNullOrEmpty()) {
                "uid $uid"
            } else {
                try {
                    pm.getApplicationLabel(pm.getApplicationInfo(pkgs[0], 0)).toString()
                } catch (e: Exception) {
                    pkgs[0]
                }
            }
        }
    }

    /** Returns a copy of [event] enriched with uid + app label. */
    fun enrich(event: ConnectionEvent): ConnectionEvent {
        val uid = ownerUid(event)
        return event.copy(uid = uid, appLabel = label(uid))
    }
}
