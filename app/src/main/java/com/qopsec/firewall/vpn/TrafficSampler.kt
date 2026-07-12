package com.qopsec.firewall.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.TrafficStats
import android.os.Process
import com.qopsec.firewall.data.AppDatabase
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
            dao.trim(System.currentTimeMillis() - RETENTION_MS)
            // Baseline = counters at start, so only bytes moved while running are counted.
            var lastRx = TrafficStats.getUidRxBytes(ownUid)
            var lastTx = TrafficStats.getUidTxBytes(ownUid)
            while (true) {
                delay(SAMPLE_MS)
                val rx = TrafficStats.getUidRxBytes(ownUid)
                val tx = TrafficStats.getUidTxBytes(ownUid)
                val dRx = (rx - lastRx).coerceAtLeast(0)   // negative = counter reset (reboot)
                val dTx = (tx - lastTx).coerceAtLeast(0)
                lastRx = rx
                lastTx = tx
                if (dRx == 0L && dTx == 0L) continue
                val hour = System.currentTimeMillis() / HOUR_MS * HOUR_MS
                if (wifiUp()) dao.add(hour, dRx, dTx, 0, 0) else dao.add(hour, 0, 0, dRx, dTx)
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
        netCallback?.let { runCatching { cm.unregisterNetworkCallback(it) } }
        netCallback = null
        transports.clear()
    }
}
