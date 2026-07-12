package com.qopsec.firewall.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.TrafficStats
import android.os.Process
import com.qopsec.firewall.data.AppDatabase
import com.qopsec.firewall.data.Diag
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap

/**
 * Measures traffic that runs THROUGH the firewall while it is up — zero extra permissions.
 *
 * Every forwarded byte crosses one of this app's protected upstream sockets, so our own
 * uid's counters ([TrafficStats.getUidRxBytes]/[TrafficStats.getUidTxBytes]) are exactly
 * the tunnel's upstream traffic. No double count: the tun fd is not a socket, so the
 * tun-side copy of each byte isn't attributed to us. Deltas are attributed to the network
 * carrying the default route (WiFi preferred when both are up, mirroring Android's own
 * routing preference) and accumulated into hourly Room buckets.
 *
 * Correctly NOT counted: apps split-tunnelled out via "Bypass firewall" (their traffic
 * never crosses our sockets) and blocked flows (never forwarded).
 */
class TrafficSampler(context: Context) {

    companion object {
        private const val SAMPLE_MS = 2000L
        const val HOUR_MS = 3_600_000L
        private const val RETENTION_MS = 400L * 24 * HOUR_MS   // ~13 months of hourly rows
        private const val SUMMARY_EVERY = 30                   // samples per FULL-diag summary (~60s)

        private fun fmt(b: Long): String = when {
            b >= 1L shl 20 -> String.format(java.util.Locale.US, "%.1f MB", b / 1048576.0)
            b >= 1L shl 10 -> String.format(java.util.Locale.US, "%.1f KB", b / 1024.0)
            else -> "$b B"
        }
    }

    private val app = context.applicationContext
    private val dao by lazy { AppDatabase.get(app).usageDao() }
    private val cm = app.getSystemService(ConnectivityManager::class.java)
    private val ownUid = Process.myUid()

    // Live non-VPN internet networks by transport, maintained by the callback below.
    private val transports = ConcurrentHashMap<Network, Int>()
    private var netCallback: ConnectivityManager.NetworkCallback? = null
    private var job: Job? = null

    private fun wifiUp(): Boolean = transports.containsValue(NetworkCapabilities.TRANSPORT_WIFI)

    fun start(scope: CoroutineScope) {
        if (job != null) return

        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return
                transports[network] = when {
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> NetworkCapabilities.TRANSPORT_WIFI
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> NetworkCapabilities.TRANSPORT_CELLULAR
                    else -> return
                }
            }

            override fun onLost(network: Network) {
                transports.remove(network)
            }
        }
        runCatching {
            cm.registerNetworkCallback(
                NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).build(),
                cb,
            )
        }
        netCallback = cb

        job = scope.launch {
            Diag.life("stats sampler started (uid=$ownUid)")
            dao.trim(System.currentTimeMillis() - RETENTION_MS)
            dao.trimApps(System.currentTimeMillis() - RETENTION_MS)
            // Baseline = counters at start, so only bytes moved while running are counted.
            var lastRx = TrafficStats.getUidRxBytes(ownUid)
            var lastTx = TrafficStats.getUidTxBytes(ownUid)
            // FULL-diag summary accumulators (byte counts only — no hostnames).
            var sumWifi = 0L
            var sumMobile = 0L
            var samples = 0
            while (true) {
                delay(SAMPLE_MS)
                val rx = TrafficStats.getUidRxBytes(ownUid)
                val tx = TrafficStats.getUidTxBytes(ownUid)
                val dRx = (rx - lastRx).coerceAtLeast(0)   // negative = counter reset (reboot)
                val dTx = (tx - lastTx).coerceAtLeast(0)
                lastRx = rx
                lastTx = tx
                val wifi = wifiUp()
                if (dRx != 0L || dTx != 0L) {
                    val hour = System.currentTimeMillis() / HOUR_MS * HOUR_MS
                    if (wifi) {
                        dao.add(hour, dRx, dTx, 0, 0)
                        sumWifi += dRx + dTx
                    } else {
                        dao.add(hour, 0, 0, dRx, dTx)
                        sumMobile += dRx + dTx
                    }
                }
                if (++samples >= SUMMARY_EVERY) {
                    if (sumWifi > 0 || sumMobile > 0) {
                        Diag.flow(
                            "stats: +${fmt(sumWifi)} wifi / +${fmt(sumMobile)} mobile last " +
                                "${SUMMARY_EVERY * SAMPLE_MS / 1000}s (transport=${if (wifi) "wifi" else "mobile"})",
                        )
                    }
                    sumWifi = 0; sumMobile = 0; samples = 0
                }
            }
        }
    }

    fun stop() {
        if (job != null) Diag.life("stats sampler stopped")
        job?.cancel()
        job = null
        netCallback?.let { runCatching { cm.unregisterNetworkCallback(it) } }
        netCallback = null
        transports.clear()
    }
}
